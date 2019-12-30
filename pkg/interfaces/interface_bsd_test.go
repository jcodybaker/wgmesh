// +build darwin freebsd openbsd

package interfaces

import "testing"

func testInNetworkNamespace(t *testing.T, f func()) {
	t.Fatalf("interfaces.testInNetworkNamespace: %w", errUnimplemented)
}
