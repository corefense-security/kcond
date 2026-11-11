package gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
)

// tree writes a small kernel. a.c is always built and b.c is behind CONFIG_B.
// Only b.c includes private.h, both include shared.h, and nothing includes
// orphan.h. It also has arm64 code, which x86 never reads.
func tree(t *testing.T) *Tree {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"Makefile":                           "VERSION = 6\nPATCHLEVEL = 18\nSUBLEVEL = 52\nEXTRAVERSION =\ninclude $(srctree)/arch/$(SRCARCH)/Makefile\ndrivers-y += drivers/\n",
		"Kconfig":                            "config MODULES\n\tbool \"modules\"\n\tmodules\n\nconfig B\n\ttristate \"b\"\n",
		"arch/x86/Kconfig":                   "config X86\n\tdef_bool y\n",
		"arch/x86/Makefile":                  "\n",
		"arch/arm64/Kconfig":                 "config ARM64\n\tdef_bool y\n",
		"arch/arm64/Makefile":                "\n",
		"arch/arm64/kernel/cpu.c":            "\n",
		"arch/arm64/Kconfig.errata":          "\n",
		"drivers/Makefile":                   "ccflags-y += -I$(src)/extra\nobj-y += a.o\nobj-$(CONFIG_B) += b.o\nobj-$(CONFIG_B) += opt/\n",
		"drivers/opt/Makefile":               "obj-y += c.o\n",
		"drivers/opt/c.c":                    "\n",
		"drivers/a.c":                        "#include <linux/shared.h>\n#include \"sub/flagged.h\"\n#ifdef CONFIG_B\n#include \"gated.h\"\n#endif\n#include \"above.h\"\n",
		"drivers/gated.h":                    "\n",
		"above.h":                            "\n",
		"drivers/b.c":                        "#include <linux/shared.h>\n#include \"private.h\"\n",
		"drivers/private.h":                  "\n",
		"drivers/orphan.h":                   "\n",
		"drivers/extra/sub/flagged.h":        "\n", // found only through an -I flag
		"include/linux/shared.h":             "#include <asm/generic-only.h>\n",
		"include/asm-generic/generic-only.h": "\n",
		"Documentation/note.rst":             "\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tr, err := Open(context.Background(), dir, builds.X86_64Build)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestVersion(t *testing.T) {
	if v := tree(t).Version; v != "6.18.52" {
		t.Errorf("Version = %q", v)
	}
}

func TestFiles(t *testing.T) {
	want := map[string]File{
		"drivers/a.c":               {Status: builds.StatusBuilt, Gate: "true"},
		"drivers/b.c":               {Status: builds.StatusBuilt, Gate: "CONFIG_B"},
		"drivers/private.h":         {Status: builds.StatusBuilt, Gate: "CONFIG_B"},
		"drivers/orphan.h":          {Status: builds.StatusHeader},
		"arch/arm64/kernel/cpu.c":   {Status: builds.StatusNotBuilt},
		"arch/arm64/Kconfig.errata": {Status: builds.StatusNotBuilt},
		"drivers/Makefile":          {Status: Skipped},
		"Documentation/note.rst":    {Status: Skipped},
		"tools/lib/bpf/relo_core.c": {Status: Skipped},
		"drivers/moved.c":           {Status: builds.StatusMissing},
		"include/linux/moved.h":     {Status: builds.StatusMissing},
	}
	tr := tree(t)
	for p, w := range want {
		f := tr.Files([]string{p})[0]
		if f.Status != w.Status || f.Gate != w.Gate {
			t.Errorf("%s: got %q %q, want %q %q", p, f.Status, f.Gate, w.Status, w.Gate)
		}
	}
}

// TestLinksAndDirGate checks where a compiled source goes, and what the
// directory of a source the tree lacks says about it.
func TestLinksAndDirGate(t *testing.T) {
	tr := tree(t)
	for p, want := range map[string][]Link{
		"drivers/a.c": {{Object: "drivers/a", Builtin: "true", Module: "false"}},
		// CONFIG_B is a tristate. At y it is built in, at m it is drivers/b.ko.
		"drivers/b.c": {{Object: "drivers/b", Builtin: "CONFIG_B=y", Module: "CONFIG_B=m"}},
		// A header has no object of its own.
		"drivers/private.h": nil,
	} {
		got := tr.Files([]string{p})[0].Links
		if len(got) != len(want) {
			t.Errorf("%s: links %v, want %v", p, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: links %v, want %v", p, got, want)
			}
		}
	}
	for p, want := range map[string]string{
		"drivers/moved.c":     "true",       // a.c beside it is always compiled
		"drivers/opt/new.c":   "CONFIG_B=y", // obj-$(CONFIG_B) += opt/, so its obj-y builds only at B=y
		"net/gone/x.c":        "",           // no source in that directory
		"include/linux/new.h": "",           // a header can be included from anywhere
	} {
		f := tr.Files([]string{p})[0]
		if f.Status != builds.StatusMissing || f.DirGate != want {
			t.Errorf("%s: got %q dir gate %q, want missing with %q", p, f.Status, f.DirGate, want)
		}
	}
}

func TestGateParses(t *testing.T) {
	f := tree(t).Files([]string{"drivers/b.c"})[0]
	e, err := kcond.Parse(f.Gate)
	if err != nil {
		t.Fatal(err)
	}
	if e.Eval(kcond.Config{"CONFIG_B": 'm'}) != kcond.True || e.Eval(kcond.Config{}) != kcond.False {
		t.Errorf("%s evaluates wrongly", f.Gate)
	}
}

func TestCompiled(t *testing.T) {
	tr := tree(t)
	off, err := tr.Compiled(kcond.Config{})
	if err != nil {
		t.Fatal(err)
	}
	on, err := tr.Compiled(kcond.Config{"CONFIG_B": 'y'})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"include/linux/shared.h", "include/asm-generic/generic-only.h", "drivers/extra/sub/flagged.h", "above.h"} {
		if off[p] != "drivers/a.c" {
			t.Errorf("%s: reached from %q, want drivers/a.c", p, off[p])
		}
	}
	for _, p := range []string{"drivers/private.h", "drivers/gated.h"} {
		if _, ok := off[p]; ok {
			t.Errorf("%s reached with CONFIG_B off", p)
		}
	}
	if on["drivers/private.h"] != "drivers/b.c" {
		t.Errorf("private.h reached from %q with b.c on", on["drivers/private.h"])
	}
}
