package agent

import (
	"net"
	"testing"

	"github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned/fake"
	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"
)

func TestRandomInCIDR(t *testing.T) {
	tcs := []struct {
		name string
		ip   net.IP
		mask net.IPMask
	}{
		{
			name: "ipv4",
			ip:   net.ParseIP("192.168.1.0"),
			mask: net.CIDRMask(24, 32),
		},
		{
			name: "ipv4 non-byte boundary",
			ip:   net.ParseIP("192.168.1.0"),
			mask: net.CIDRMask(28, 32),
		},
		{
			name: "ipv6",
			ip:   net.ParseIP("fe80::4f:96ff:fe30:ef2c"),
			mask: net.CIDRMask(64, 128),
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ipnet := net.IPNet{
				IP:   tc.ip,
				Mask: tc.mask,
			}
			out, err := randomInCIDR(&ipnet)
			require.NoError(t, err)
			require.True(t, ipnet.Contains(out.IP))
			require.Equal(t, tc.mask, out.Mask)
		})
	}
}

func TestCanonicalIPInCIDR(t *testing.T) {
	tcs := []struct {
		name        string
		cidr        string
		expectBytes int
		expectMask  net.IPMask
	}{
		{
			name:        "ipv4",
			cidr:        "192.168.1.0/28",
			expectBytes: net.IPv4len,
			expectMask:  net.CIDRMask(28, 32),
		},
		{
			name:        "ipv6",
			cidr:        "fe80::/10",
			expectBytes: net.IPv6len,
			expectMask:  net.CIDRMask(10, 128),
		},
		{
			name:        "ipv6 encoded ipv4",
			cidr:        "::ffff:c0a8:100/124", // 192.168.1.0/28
			expectBytes: net.IPv4len,
			expectMask:  net.CIDRMask(28, 32),
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tc.cidr)
			require.NoError(t, err)
			out, err := canonicalIPInCIDR(cidr)
			require.NoError(t, err)
			require.NotNil(t, out)
			outOnes, outBits := out.Mask.Size()
			expectOnes, expectBits := tc.expectMask.Size()
			require.Equal(t, expectOnes, outOnes)
			require.Equal(t, expectBits, outBits)
			require.Equal(t, tc.expectBytes, len(out.IP))
		})
	}
}

func TestDefaultRangeEnd(t *testing.T) {
	tcs := []struct {
		name      string
		cidr      string
		expectEnd net.IP
	}{
		{
			name:      "IPv4 /25",
			cidr:      "192.168.1.0/25",
			expectEnd: net.ParseIP("192.168.1.126"),
		},
		{
			name:      "IPv4 /31",
			cidr:      "10.0.0.0/31",
			expectEnd: net.ParseIP("10.0.0.1"),
		},
		{
			name:      "IPv6 /31",
			cidr:      "fe80::/10",
			expectEnd: net.ParseIP("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		},
		{
			name:      "IPv6 encoded IPv4",
			cidr:      "::ffff:c0a8:100/121", // 192.168.1.0/25
			expectEnd: net.ParseIP("192.168.1.126"),
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tc.cidr)
			require.NoError(t, err)
			end, err := defaultRangeEnd(cidr)
			require.NoError(t, err)
			require.Truef(t, tc.expectEnd.Equal(end), "expected(%s) != actual(%s)", tc.expectEnd.String(), end.String())
		})
	}
}

func TestDefaultRangeStart(t *testing.T) {
	tcs := []struct {
		name        string
		cidr        string
		expectStart net.IP
	}{
		{
			name:        "IPv4 /25",
			cidr:        "192.168.1.0/25",
			expectStart: net.ParseIP("192.168.1.1"),
		},
		{
			name:        "IPv4 /31",
			cidr:        "10.0.0.0/31",
			expectStart: net.ParseIP("10.0.0.0"),
		},
		{
			name:        "IPv6 /31",
			cidr:        "fe80::/10",
			expectStart: net.ParseIP("fe80::0"),
		},
		{
			name:        "IPv6 encoded IPv4",
			cidr:        "::ffff:c0a8:100/121", // 192.168.1.0/25
			expectStart: net.ParseIP("192.168.1.1"),
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tc.cidr)
			require.NoError(t, err)
			end, err := defaultRangeStart(cidr)
			require.NoError(t, err)
			require.Truef(t, tc.expectStart.Equal(end), "expected(%s) != actual(%s)", tc.expectStart.String(), end.String())
		})
	}
}

func TestIncrementIPNetV4(t *testing.T) {
	tcs := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "simple",
			in:       "192.168.1.1/24",
			expected: "192.168.1.2/24",
		},
		{
			name:     "rollover",
			in:       "192.168.1.255/24",
			expected: "192.168.1.0/24",
		},
		{
			name:     "grand rollover",
			in:       "255.255.255.255/24",
			expected: "255.255.255.0/24",
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			inIP, inIPNet, err := net.ParseCIDR(tc.in)
			require.NoError(t, err)
			inIPNet.IP = inIP

			expectedIP, expectedIPNet, err := net.ParseCIDR(tc.expected)
			require.NoError(t, err)
			expectedIPNet.IP = expectedIP

			expectedIPNet, err = canonicalIPInCIDR(expectedIPNet)
			require.NoError(t, err)

			out, err := incrementIP(inIPNet)
			require.NoError(t, err)
			require.Equal(t, expectedIPNet, out)
		})
	}
}

func TestIPPoolFindAddress(t *testing.T) {
	tcs := []struct {
		name        string
		pool        *ipPool
		expectError string
		expectIPs   []string
		expectMask  net.IPMask
	}{
		{
			name: "success",
			pool: &ipPool{
				ranges: []*ipRange{
					{
						cidr: net.IPNet{
							IP:   net.ParseIP("10.0.0.0"),
							Mask: net.CIDRMask(30, 32),
						},
						start: net.ParseIP("10.0.0.1"),
						end:   net.ParseIP("10.0.0.2"),
					},
				},
				inUse: map[string]struct{}{
					"10.0.0.2": struct{}{},
				},
			},
			expectIPs:  []string{"10.0.0.1"},
			expectMask: net.CIDRMask(30, 32),
		},
		{
			name: "slash-thirty-one",
			pool: &ipPool{
				ranges: []*ipRange{
					{
						cidr: net.IPNet{
							IP:   net.ParseIP("10.0.0.0"),
							Mask: net.CIDRMask(31, 32),
						},
						start: net.ParseIP("10.0.0.0"),
						end:   net.ParseIP("10.0.0.1"),
					},
				},
				inUse: map[string]struct{}{
					"10.0.0.1": struct{}{},
				},
			},
			expectIPs:  []string{"10.0.0.0"},
			expectMask: net.CIDRMask(31, 32),
		},
		{
			name: "multiple-ranges",
			pool: &ipPool{
				ranges: []*ipRange{
					{
						cidr: net.IPNet{
							IP:   net.ParseIP("10.0.0.0"),
							Mask: net.CIDRMask(31, 32),
						},
						start: net.ParseIP("10.0.0.0"),
						end:   net.ParseIP("10.0.0.1"),
					},
					{
						cidr: net.IPNet{
							IP:   net.ParseIP("10.0.1.0"),
							Mask: net.CIDRMask(31, 32),
						},
						start: net.ParseIP("10.0.1.0"),
						end:   net.ParseIP("10.0.1.1"),
					},
				},
				inUse: map[string]struct{}{
					"10.0.0.0": struct{}{},
					"10.0.0.1": struct{}{},
					"10.0.1.1": struct{}{},
				},
			},
			expectIPs:  []string{"10.0.1.0"},
			expectMask: net.CIDRMask(31, 32),
		},
		{
			name: "no addr available",
			pool: &ipPool{
				ranges: []*ipRange{
					{
						cidr: net.IPNet{
							IP:   net.ParseIP("10.0.0.0"),
							Mask: net.CIDRMask(31, 32),
						},
						start: net.ParseIP("10.0.0.0"),
						end:   net.ParseIP("10.0.0.1"),
					},
					{
						cidr: net.IPNet{
							IP:   net.ParseIP("10.0.1.0"),
							Mask: net.CIDRMask(31, 32),
						},
						start: net.ParseIP("10.0.1.0"),
						end:   net.ParseIP("10.0.1.1"),
					},
				},
				inUse: map[string]struct{}{
					"10.0.0.0": struct{}{},
					"10.0.0.1": struct{}{},
					"10.0.1.0": struct{}{},
					"10.0.1.1": struct{}{},
				},
			},
			expectError: errNoAvailableIPAddresses.Error(),
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.pool.findAddress()
			if tc.expectError != "" {
				require.EqualError(t, err, tc.expectError)
				return
			}
			require.NoError(t, err)
			require.Contains(t, tc.expectIPs, got.IP.String())
			require.Equal(t, tc.expectMask, got.Mask)
		})
	}
}

func TestRegistryIPAMLoadPool(t *testing.T) {
	tcs := []struct {
		name         string
		k8sippool    *wgk8s.IPPool
		claims       []string
		expectName   string
		expectInUse  []string
		expectRanges []*ipRange
		expectError  string
	}{
		{
			name: "success",
			k8sippool: &wgk8s.IPPool{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "name"},
				Spec: wgk8s.IPPoolSpec{
					Reserved: []string{"192.168.1.1"},
					IPRanges: []wgk8s.IPRange{
						{
							CIDR: "192.168.1.0/24",
						},
					},
				},
			},
			claims:      []string{"192.168.1.2"},
			expectName:  "ns:name",
			expectInUse: []string{"192.168.1.1", "192.168.1.2"},
			expectRanges: []*ipRange{
				&ipRange{
					cidr: net.IPNet{
						Mask: net.CIDRMask(24, 32),
						IP:   net.ParseIP("192.168.1.0").To4(),
					},
					start: net.ParseIP("192.168.1.1").To4(),
					end:   net.ParseIP("192.168.1.254").To4(),
				},
			},
		},
		{
			name: "multiple ranges",
			k8sippool: &wgk8s.IPPool{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "name"},
				Spec: wgk8s.IPPoolSpec{
					Reserved: []string{"192.168.1.1"},
					IPRanges: []wgk8s.IPRange{
						{
							CIDR: "192.168.1.0/24",
						},
						{
							CIDR:  "10.1.2.64/28",
							Start: "10.1.2.66",
							End:   "10.1.2.75",
						},
					},
				},
			},
			claims:      []string{"192.168.1.2"},
			expectName:  "ns:name",
			expectInUse: []string{"192.168.1.1", "192.168.1.2"},
			expectRanges: []*ipRange{
				&ipRange{
					cidr: net.IPNet{
						Mask: net.CIDRMask(24, 32),
						IP:   net.ParseIP("192.168.1.0").To4(),
					},
					start: net.ParseIP("192.168.1.1").To4(),
					end:   net.ParseIP("192.168.1.254").To4(),
				},
				&ipRange{
					cidr: net.IPNet{
						Mask: net.CIDRMask(28, 32),
						IP:   net.ParseIP("10.1.2.64").To4(),
					},
					start: net.ParseIP("10.1.2.66"),
					end:   net.ParseIP("10.1.2.75"),
				},
			},
		},
		{
			name: "start out of range",
			k8sippool: &wgk8s.IPPool{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "name"},
				Spec: wgk8s.IPPoolSpec{
					IPRanges: []wgk8s.IPRange{
						{
							CIDR:  "192.168.1.0/24",
							Start: "192.168.5.1",
						},
					},
				},
			},
			expectError: `ipv4.start "192.168.5.1" was not contained by cidr "192.168.1.0/24"`,
		},
		{
			name: "end out of range",
			k8sippool: &wgk8s.IPPool{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "name"},
				Spec: wgk8s.IPPoolSpec{
					IPRanges: []wgk8s.IPRange{
						{
							CIDR: "192.168.1.0/24",
							End:  "192.168.5.1",
						},
					},
				},
			},
			expectError: `ipv4.end "192.168.5.1" was not contained by cidr "192.168.1.0/24"`,
		},
	}
	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := &registryIPAM{
				name:      t.Name(),
				clientset: fake.NewSimpleClientset(),
			}

			_, err := r.clientset.WgmeshV1alpha1().IPPools(tc.k8sippool.GetNamespace()).Create(tc.k8sippool)
			require.NoError(t, err)
			for _, claim := range tc.claims {
				_, err = r.clientset.WgmeshV1alpha1().IPClaims(tc.k8sippool.GetNamespace()).Create(&wgk8s.IPClaim{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: claimName(tc.k8sippool.Name, claim)},
					Spec:       wgk8s.IPClaimSpec{IP: claim},
				})
				require.NoError(t, err)
			}
			ipPool, err := r.loadPool(tc.k8sippool.GetNamespace(), tc.k8sippool.GetName())
			if tc.expectError != "" {
				require.EqualError(t, err, tc.expectError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectName, ipPool.name)
			expectInUse := make(map[string]struct{}, len(tc.expectInUse))
			for _, inUse := range tc.expectInUse {
				expectInUse[inUse] = struct{}{}
			}
			require.Equal(t, expectInUse, ipPool.inUse)
			require.ElementsMatch(t, tc.expectRanges, ipPool.ranges)
		})
	}
}
