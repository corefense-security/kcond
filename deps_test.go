package kcond

import (
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/corefense-security/kcond"

// TestStandardLibraryOnly guards the rule the module lives by: its
// packages, tests included, depend on the standard library and on each
// other only.
func TestStandardLibraryOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "-f",
		"{{if not .Standard}}{{.ImportPath}}{{end}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for line := range strings.Lines(string(out)) {
		// A test variant prints as "pkg [pkg.test]"; the test binary as
		// "pkg.test".
		dep, _, _ := strings.Cut(strings.TrimSpace(line), " [")
		if dep == "" || strings.HasSuffix(dep, ".test") {
			continue
		}
		if dep != module && !strings.HasPrefix(dep, module+"/") {
			t.Errorf("%s is neither of the module nor of the standard library", dep)
		}
	}
}
