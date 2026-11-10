package dotconfig

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/corefense-security/kcond/builds"
)

// gzipped compresses data as gzip does /proc/config.gz.
func gzipped(t *testing.T, data string) string {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A gzip file, such as /proc/config.gz, reads as the config it holds.
func TestReadGzip(t *testing.T) {
	const config = "# Linux/x86 6.12.43 Kernel Configuration\nCONFIG_NET=y\nCONFIG_INET=m\n"
	f, err := Read([]byte(gzipped(t, config)))
	if err != nil || f.Version != "6.12.43" || f.Build != builds.X86_64Build || f.Config["CONFIG_INET"] != 'm' {
		t.Errorf("gzip config = %+v, %v", f, err)
	}
	text, err := Text([]byte(gzipped(t, config)))
	if err != nil || string(text) != config {
		t.Errorf("ConfigText = %q, %v", text, err)
	}
	if text, err := Text([]byte(config)); err != nil || string(text) != config {
		t.Errorf("ConfigText of plain text = %q, %v", text, err)
	}
}

// Files that are not configs say what they are instead.
func TestReadErrors(t *testing.T) {
	for _, tc := range []struct{ data, msg string }{
		{"\x1f\x8b\x08\x00", "does not decompress"},
		{"CONFIG_A=y\n\x00", "binary"},
		{strings.Repeat("A", MaxBytes+1), "larger than 512 KiB"},
		{"# Linux/x86 6.12.43 Kernel Configuration\nCONFIG_A=y", "cut off"},
		{"", "not a kernel .config"},
		// A small file that decompresses to more than any config does.
		{"gzip bomb", "larger than 512 KiB"},
	} {
		if tc.data == "gzip bomb" {
			tc.data = gzipped(t, strings.Repeat("CONFIG_A=y\n", MaxBytes/10))
		}
		if _, err := Read([]byte(tc.data)); err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("Read(%.20q) = %v, want an error naming %q", tc.data, err, tc.msg)
		}
	}
}

func TestParse(t *testing.T) {
	off := strings.Repeat("# CONFIG_X is not set\n", partialOff)
	for _, tc := range []struct {
		name, data     string
		version, build string
		partial, err   bool
	}{
		{"x86 header", "#\n# Automatically generated file; DO NOT EDIT.\n# Linux/x86 6.12.107 Kernel Configuration\n#\nCONFIG_A=y\n", "6.12.107", "x86_64", false, false},
		{"x86_64 header", "# Linux/x86_64 7.2.8-arch1 Kernel Configuration\nCONFIG_A=y\n", "7.2.8-arch1", "x86_64", false, false},
		{"i386 header", "# Linux/i386 7.3.0-rc6 Kernel Configuration\nCONFIG_X86_32=y\n", "7.3.0-rc6", "i386", false, false},
		{"x86 header, 32-bit", "# Linux/x86 6.6.1 Kernel Configuration\nCONFIG_X86_32=y\nCONFIG_X86=y\n", "6.6.1", "i386", false, false},
		{"arm64 header", "# Linux/arm64 6.12.43 Kernel Configuration\nCONFIG_ARM64=y\n", "6.12.43", "arm64", false, false},
		{"plus suffix", "# Linux/x86 6.12.43+deb13 Kernel Configuration\nCONFIG_A=y\n", "6.12.43+deb13", "x86_64", false, false},
		// Without a header the architecture symbol decides, and few
		// options off make a partial config.
		{"symbol", "CONFIG_ARM64=y\nCONFIG_NET=y\n", "", "arm64", true, false},
		{"x86-64 symbol", "CONFIG_X86_64=y\n", "", "x86_64", true, false},
		{"ppc symbol", "CONFIG_PPC=y\nCONFIG_PPC64=y\n" + off, "", "powerpc", false, false},
		{"no arch", "CONFIG_NET=y\n", "", "", true, false},
		{"unsupported arch", "# Linux/mips 6.1.0 Kernel Configuration\nCONFIG_MIPS=y\n", "", "", false, true},
		{"not a config", "hello\n# CONFIG_X is not set\n", "", "", false, true},
		// kconfig ends a file with a newline, so one that stops in the
		// middle of a line was cut off.
		{"cut off", "# Linux/x86 6.12.43 Kernel Configuration\nCONFIG_A=y\n# CONFIG_B is no", "", "", false, true},
		{"empty", "", "", "", false, true},
		{"binary", "CONFIG_A=y\n\x00\x01\x02\n", "", "", false, true},
	} {
		f, err := Parse([]byte(tc.data))
		if (err != nil) != tc.err {
			t.Errorf("%s: error = %v", tc.name, err)
			continue
		}
		if err != nil {
			continue
		}
		if f.Version != tc.version || f.Build != tc.build || f.Partial != tc.partial || len(f.Config) == 0 {
			t.Errorf("%s: version %q build %q partial %v (%d options), want %q %q %v", tc.name,
				f.Version, f.Build, f.Partial, len(f.Config), tc.version, tc.build, tc.partial)
		}
	}
}
