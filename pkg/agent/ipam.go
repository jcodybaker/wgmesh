package agent

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"regexp"
	"strings"

	wgmeshCS "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"
	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errNoAvailableIPAddresses = errors.New("no available IP addresses")

var claimIPRegexp = regexp.MustCompile(`[^a-f0-9]`)

type registryIPAM struct {
	name      string
	clientset wgmeshCS.Interface
	claims    []wgk8s.IPClaim
}

type ipPool struct {
	// name is currently just used for error messages.
	name   string
	inUse  map[string]struct{}
	ranges []*ipRange
}

type ipRange struct {
	cidr  net.IPNet
	start net.IP
	end   net.IP
}

func (r *registryIPAM) ClaimIPv4(namespace, poolName string) (*net.IPNet, error) {

	return nil, nil
}

func (r *registryIPAM) loadPool(namespace, poolName string) (*ipPool, error) {
	pool := &ipPool{
		name:  fmt.Sprintf("%s:%s", namespace, poolName),
		inUse: make(map[string]struct{}),
	}

	poolRecord, err := r.clientset.
		WgmeshV1alpha1().
		IPPools(namespace).
		Get(poolName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("loading pool %s:%s: %w", namespace, poolName, err)
	}

	// Shuffle the order of ranges so we start with a random one and can visit all if needed.
	rangeIndexes, err := randPerm(len(poolRecord.Spec.IPRanges))
	if err != nil {
		return nil, fmt.Errorf("shuffling ip ranges: %w", err)
	}
	for _, i := range rangeIndexes {
		ipr := poolRecord.Spec.IPRanges[i]
		_, cidr, err := net.ParseCIDR(ipr.CIDR)
		if err != nil {
			return nil, fmt.Errorf("parsing pool \"%s:%s\" ipv4.cidr %q",
				namespace, poolName, ipr.CIDR)
		}
		var start, end net.IP
		if ipr.Start != "" {
			start = net.ParseIP(ipr.Start)
			if start == nil {
				return nil, fmt.Errorf("parsing pool \"%s:%s\" ipv4.start %q",
					namespace, poolName, ipr.Start)
			}
			if !cidr.Contains(start) {
				return nil, fmt.Errorf("pool \"%s:%s\" ipv4.start %q was not contained by cidr %q",
					namespace, poolName, ipr.Start, cidr.String())
			}
		} else {
			start, err = defaultRangeStart(cidr)
			if err != nil {
				return nil, fmt.Errorf("calculating default end address for pool \"%s:%s\": %w",
					namespace, poolName, err)
			}
		}
		if ipr.End != "" {
			end = net.ParseIP(ipr.End)
			if end == nil {
				return nil, fmt.Errorf("parsing pool \"%s:%s\" ipv4.end %q",
					namespace, poolName, ipr.End)
			}
			if !cidr.Contains(end) {
				return nil, fmt.Errorf("pool \"%s:%s\" ipv4.end %q was not contained by cidr %q",
					namespace, poolName, ipr.End, cidr.String())
			}
		} else {
			end, err = defaultRangeEnd(cidr)
			if err != nil {
				return nil, fmt.Errorf("calculating default end address for pool \"%s:%s\": %w",
					namespace, poolName, err)
			}
		}
		pool.ranges = append(pool.ranges, &ipRange{
			cidr:  *cidr,
			start: start,
			end:   end,
		})
	}

	for _, ip := range poolRecord.Spec.Reserved {
		// These are user provided, parse them and then serialize them in canonical format.
		reserved := net.ParseIP(ip)
		if reserved == nil {
			return nil, fmt.Errorf("parsing reserved ip %q", ip)
		}
		pool.inUse[reserved.String()] = struct{}{}
	}

	claims, err := r.clientset.
		WgmeshV1alpha1().
		IPClaims(namespace).
		List(metav1.ListOptions{
			LabelSelector: "",
		})
	if err != nil {
		return nil, fmt.Errorf("loading claims %s:%s: %w", namespace, poolName, err)
	}

	for _, claim := range claims.Items {
		// These are user provided, parse them and then serialize them in canonical format.
		reserved := net.ParseIP(claim.Spec.IP)
		if reserved == nil {
			return nil, fmt.Errorf(`parsing reserved claim "%s:%s" - ip %q`,
				namespace, claim.GetName(), claim.Spec.IP)
		}
		pool.inUse[reserved.String()] = struct{}{}
	}

	return pool, nil
}

// findAddress finds an available IP in the provided CIDR.
func (p *ipPool) findAddress() (*net.IPNet, error) {
	for _, r := range p.ranges {
		// Select a random IP in the range and increment until we find a free address or find ourselves
		// back where we started.
		firstTry, err := randomInCIDR(&r.cidr)
		if err != nil {
			return nil, fmt.Errorf("selecting random ip: %w", err)
		}
		var currentAddr *net.IPNet
		for {
			if currentAddr == nil {
				currentAddr = firstTry
			} else {
				currentAddr, err = incrementIP(currentAddr)
				if err != nil {
					return nil, err
				}
				if currentAddr.IP.Equal(firstTry.IP) {
					break // next range
				}
			}
			isBeforeStart, err := ipGreater(false, currentAddr.IP, r.start)
			if err != nil {
				return nil, err
			}
			if isBeforeStart {
				continue
			}
			isAfterEnd, err := ipLess(false, currentAddr.IP, r.start)
			if err != nil {
				return nil, err
			}
			if isAfterEnd {
				continue
			}
			if _, ok := p.inUse[currentAddr.IP.String()]; ok {
				continue
			}
			return currentAddr, nil
		}
	}
	return nil, errNoAvailableIPAddresses
}

func randomInCIDR(cidr *net.IPNet) (*net.IPNet, error) {
	cidr, err := canonicalIPInCIDR(cidr)
	if err != nil {
		return nil, err
	}
	notMask := byteSliceNot([]byte(cidr.Mask))
	randAddr := make([]byte, len(cidr.IP))
	_, err = rand.Read(randAddr)
	if err != nil {
		return nil, err
	}
	var out net.IPNet
	out.Mask = cidr.Mask
	significantBits, err := byteSliceAnd(notMask, randAddr)
	if err != nil {
		return nil, err
	}
	out.IP, err = byteSliceOr(significantBits, cidr.IP)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// canonicalIPInCIDR return the provided CIDR as a 4-byte net.IP for IPv4 addresses (including
// those originally specified in IPv6 CIDR format), or a 16-byte net.IP for IPv6. canonicalIPInCIDR
// assumes the IP property has the masked portion zeroed (as net.ParseCIDR() does).
func canonicalIPInCIDR(in *net.IPNet) (*net.IPNet, error) {
	bits, size := in.Mask.Size()
	var out net.IPNet
	out.Mask = in.Mask
	switch size {
	case net.IPv4len * 8: // IPv4
		out.IP = in.IP.To4()
		if out.IP == nil {
			return nil, fmt.Errorf(
				"net.IPNet (%q) had IPv4 mask w/ non-IPv4 network",
				in.String(),
			)
		}
	case net.IPv6len * 8: // IPv6
		out.IP = in.IP.To4()
		if out.IP != nil { // IPv6 encoded IPv4
			if bits < 96 {
				return nil, fmt.Errorf("IPv6 CIDR includes both v4 and v6 space: %q", in.String())
			}
			out.Mask = net.CIDRMask(bits-96, net.IPv4len*8)
			return &out, nil
		}
		out.IP = in.IP.To16()
		if out.IP == nil {
			return nil, fmt.Errorf("invalid network address: %q", in.IP.String())
		}
	default:
		return nil, fmt.Errorf("invalid mask: %s", in.Mask.String())
	}
	return &out, nil
}

func byteSliceAnd(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("bitwise AND called w/ different lengths: len(a)=%d len(b)=%d", len(a), len(b))
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] & b[i]
	}
	return out, nil
}

func byteSliceOr(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("bitwise OR called w/ different lengths: len(a)=%d len(b)=%d", len(a), len(b))
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] | b[i]
	}
	return out, nil
}

func byteSliceNot(a []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = ^a[i]
	}
	return out
}

// ipGreater returns true if a > b and if orEqual==true, true if equal.
func ipGreater(orEqual bool, a, b net.IP) (bool, error) {
	if len(a) != len(b) {
		a = a.To16()
		b = b.To16()
	}
	if len(a) != len(b) {
		return false, fmt.Errorf("unable to compare addresses of different bit length: len(a)=%d len(b)=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] == b[i] {
			continue
		}
		return a[i] > b[i], nil
	}
	return orEqual, nil
}

func ipLess(orEqual bool, a, b net.IP) (bool, error) {
	return ipGreater(orEqual, b, a)
}

func defaultRangeEnd(cidr *net.IPNet) (net.IP, error) {
	cidr, err := canonicalIPInCIDR(cidr)
	if err != nil {
		return nil, err
	}
	maskOnes, maskBits := cidr.Mask.Size()
	notMask := byteSliceNot([]byte(cidr.Mask))
	out, err := byteSliceOr(notMask, cidr.IP)
	if err != nil {
		return nil, err
	}

	if maskBits == (net.IPv4len*8) && maskOnes < 31 {
		// We implicitly reserve the broadcast address for IPv4 subnets larger /31's
		out[len(out)-1]--
	}
	return out, nil
}

func defaultRangeStart(cidr *net.IPNet) (net.IP, error) {
	cidr, err := canonicalIPInCIDR(cidr)
	if err != nil {
		return nil, err
	}
	maskOnes, maskBits := cidr.Mask.Size()
	start := make(net.IP, len(cidr.IP))
	copy(start, cidr.IP)
	if maskBits == (net.IPv4len*8) && maskOnes < 31 {
		// We implicitly reserve the network address for IPv4 subnets larger /31's
		start[len(start)-1]++
	}
	return start, nil
}

// incrementIPNetV4
func incrementIP(in *net.IPNet) (*net.IPNet, error) {
	in, err := canonicalIPInCIDR(in)
	if err != nil {
		return nil, err
	}
	// Copy and bump the IP
	ip := make(net.IP, len(in.IP))
	copy(ip, in.IP)
	byteSliceIncrement(ip)

	// prefix part of the addr
	netAddr, err := byteSliceAnd(in.IP, in.Mask)
	if err != nil {
		return nil, err
	}

	// significant part of the addr
	notMask := byteSliceNot(in.Mask)
	sig, err := byteSliceAnd(ip, notMask)
	if err != nil {
		return nil, err
	}

	// Build the whole thing
	out := net.IPNet{
		Mask: in.Mask,
	}
	out.IP, err = byteSliceOr(sig, netAddr)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// byteSliceIncrement increments the byte array as big-endian.
func byteSliceIncrement(b []byte) {
	last := len(b) - 1
	b[last] = b[last] + 1
	if b[last] == 0 && last != 1 {
		byteSliceIncrement(b[:last-1])
	}
}

func randPerm(n int) ([]int, error) {
	seedB := make([]byte, 8)
	_, err := rand.Read(seedB)
	if err != nil {
		return nil, err
	}
	seed, _ := binary.Varint(seedB)
	mrand := mathrand.New(mathrand.NewSource(seed))
	return mrand.Perm(n), nil
}

func claimName(pool, ip string) string {
	return fmt.Sprintf("%s-%s", pool, claimIPRegexp.ReplaceAllString(strings.ToLower(ip), "-"))
}
