package builds

import (
	"testing"

	"github.com/corefense-security/kcond"
)

func p(t *testing.T, s string) *kcond.Expr {
	t.Helper()
	e, err := kcond.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPathArch(t *testing.T) {
	for p, want := range map[string]string{
		"arch/x86/kernel/setup.c":    "x86",
		"arch/x86_64/kernel/setup.c": "x86",
		// x86-64 builds before v2.6.24 compiled some of arch/i386.
		"arch/i386/kernel/setup.c":    "x86",
		"arch/arm64/include/asm/io.h": "arm64",
		// User-mode Linux on an x86 host is not part of an x86 kernel.
		"arch/x86/um/asm/processor.h": "um",
		"include/linux/fs.h":          "",
		// lib/crypto, lib/crc and lib/raid keep each arch's assembly and
		// glue code in its own directory.
		"lib/crypto/arm64/sha3.h":        "arm64",
		"lib/crypto/powerpc/md5-asm.S":   "powerpc",
		"lib/crypto/tests/sha3_kunit.c":  "",
		"lib/crypto/sha3.c":              "",
		"lib/crc/loongarch/crc32.h":      "loongarch",
		"lib/crc/tests/crc_kunit.c":      "",
		"lib/raid/raid6/x86/pq_arch.h":   "x86",
		"lib/raid/xor/um/xor_arch.h":     "um",
		"lib/raid/xor/alpha/xor.c":       "alpha",
		"lib/raid/xor/tests/xor_kunit.c": "",
		"lib/raid/xor/xor-core.c":        "",
	} {
		if got := PathArch(p); got != want {
			t.Errorf("PathArch(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestCombine(t *testing.T) {
	tr := kcond.Const(true)
	for _, tc := range []struct {
		name    string
		files   []FileCond
		want    string
		unknown bool
	}{
		{"source and region", []FileCond{
			{Status: StatusBuilt, Kbuild: p(t, "CONFIG_A"), Region: p(t, "CONFIG_R")},
		}, "CONFIG_A && CONFIG_R", false},
		{"two sources", []FileCond{
			{Status: StatusBuilt, Kbuild: p(t, "CONFIG_A"), Region: tr},
			{Status: StatusBuilt, Kbuild: p(t, "CONFIG_B"), Region: tr},
		}, "CONFIG_A || CONFIG_B", false},
		{"headers ignored next to sources", []FileCond{
			{Status: StatusBuilt, Kbuild: p(t, "CONFIG_A"), Region: tr},
			{Header: true, Status: StatusHeader, Region: tr},
		}, "CONFIG_A", false},
		{"built header counts next to sources", []FileCond{
			{Status: StatusBuilt, Kbuild: p(t, "CONFIG_A"), Region: tr},
			{Header: true, Status: StatusBuilt, Kbuild: p(t, "CONFIG_H"), Region: p(t, "CONFIG_R")},
		}, "CONFIG_A || (CONFIG_H && CONFIG_R)", false},
		{"built header leaves other headers in", []FileCond{
			{Header: true, Status: StatusBuilt, Kbuild: p(t, "CONFIG_H"), Region: tr},
			{Header: true, Status: StatusHeader, Region: p(t, "CONFIG_P")},
		}, "CONFIG_H || CONFIG_P", false},
		{"unlisted source", []FileCond{
			{Status: StatusBuilt, Kbuild: p(t, "CONFIG_A"), Region: tr},
			{Status: StatusUnlisted, Region: tr},
		}, "CONFIG_A", true},
		{"other arch only", []FileCond{
			{Status: StatusNotBuilt, Region: tr},
		}, "false", false},
		{"header region", []FileCond{
			{Header: true, Status: StatusHeader, Region: p(t, "CONFIG_H=y")},
		}, "CONFIG_H=y", false},
		{"plain header", []FileCond{
			{Header: true, Status: StatusHeader, Region: tr},
		}, "", true},
		{"dead header region", []FileCond{
			{Header: true, Status: StatusHeader, Region: kcond.Const(false)},
		}, "false", false},
		{"no files", nil, "", true},
	} {
		c, unknown := Combine(tc.files)
		got := ""
		if c != nil {
			got = c.String()
		}
		if got != tc.want || unknown != tc.unknown {
			t.Errorf("%s: Combine = %q, %v; want %q, %v", tc.name, got, unknown, tc.want, tc.unknown)
		}
	}
}
