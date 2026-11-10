package kbuild

import (
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/corefense-security/kcond"
)

// A .c or .S file a listed source #includes is built with it, under the
// condition of the directive's line, as well as under its own Makefile
// condition.
func TestIncludes(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":              "core-y += kernel/ lib/\ndrivers-y += drivers/ sound/\n",
		"kernel/Makefile":       "obj-y += sched/ bpf/\n",
		"kernel/sched/Makefile": "obj-y += build_policy.o\n",
		"kernel/sched/build_policy.c": `
#include "rt.c"
#ifdef CONFIG_SCHED_CLASS_EXT
# include "ext/ext.c"
#endif
`,
		"kernel/sched/rt.c": "",
		// Chains resolve; the name is looked up next to the including file.
		"kernel/sched/ext/ext.c":  "#include \"idle.c\"\n",
		"kernel/sched/ext/idle.c": "",
		// tools/ is never entered, yet the kernel compiles this file.
		"kernel/bpf/Makefile":       "obj-$(CONFIG_BPF_SYSCALL) += relo_core.o\n",
		"kernel/bpf/relo_core.c":    "#include \"../../tools/lib/bpf/relo_core.c\"\n",
		"tools/lib/bpf/relo_core.c": "",
		// A name not next to the file is looked up in the directories
		// above it, as i915's -I$(src) finds it.
		"drivers/Makefile":         "obj-$(CONFIG_DRM_I915) += i915/\n",
		"drivers/i915/Makefile":    "obj-y += gt/\n",
		"drivers/i915/gt/Makefile": "obj-y += intel_timeline.o\n",
		"drivers/i915/gt/intel_timeline.c": `
#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "gt/selftests/mock_timeline.c"
#endif
`,
		"drivers/i915/gt/selftests/mock_timeline.c": "",
		// A listed file another listed unit includes is built under
		// either condition.
		"sound/Makefile":        "obj-$(CONFIG_SND_MSND_PINNACLE) += msnd_pinnacle.o\nobj-$(CONFIG_SND_MSND_CLASSIC) += msnd_classic.o\n",
		"sound/msnd_classic.c":  "#include \"msnd_pinnacle.c\"\n",
		"sound/msnd_pinnacle.c": "",
		"lib/Makefile":          "obj-y += dead.o odd.o\n",
		// Neither a dropped region nor a comment includes a file.
		"lib/dead.c":      "#if 0\n#include \"never.c\"\n#endif\n/*\n#include \"commented.c\"\n*/\n",
		"lib/never.c":     "",
		"lib/commented.c": "",
		// Unbalanced directives leave the include unconditional.
		"lib/odd.c":      "#endif\n#include \"odd_part.c\"\n",
		"lib/odd_part.c": "",
		// Only unlisted files include it, so its condition stays unknown.
		"arch/x86/boot/main.c": "#include \"../../../lib/boot.c\"\n",
		"lib/boot.c":           "",
		// Generated files are not in the tree.
		"lib/table.c": "#include \"generated_table.c\"\n",
	})
	expect(t, r, map[string]string{
		"kernel/sched/rt.c":                         "true",
		"kernel/sched/ext/ext.c":                    "CONFIG_SCHED_CLASS_EXT=y",
		"kernel/sched/ext/idle.c":                   "CONFIG_SCHED_CLASS_EXT=y",
		"tools/lib/bpf/relo_core.c":                 "CONFIG_BPF_SYSCALL",
		"drivers/i915/gt/selftests/mock_timeline.c": "CONFIG_DRM_I915=y && CONFIG_DRM_I915_SELFTEST",
		"sound/msnd_pinnacle.c":                     "CONFIG_SND_MSND_CLASSIC || CONFIG_SND_MSND_PINNACLE",
		"lib/never.c":                               "false",
		"lib/odd_part.c":                            "true",
		"lib/commented.c":                           "",
	})
	if _, st := r.Lookup("lib/boot.c"); st != Unlisted {
		t.Errorf("lib/boot.c: %v, want unlisted", st)
	}
	if got := r.Includes.Targets["lib/boot.c"]; len(got) != 1 || got[0].From != "arch/x86/boot/main.c" {
		t.Errorf("Includes[lib/boot.c] = %v, want arch/x86/boot/main.c", got)
	}
}

// Crawl takes the directives it is given instead of scanning the tree.
func TestGivenIncludes(t *testing.T) {
	inc := &Includes{Targets: map[string][]Include{"lib/part.c": {{From: "lib/a.c", Cond: kcond.Var("CONFIG_X", kcond.Enabled)}}}}
	r, err := Crawl(tree(map[string]string{
		"Makefile":     "core-y += lib/\n",
		"lib/Makefile": "obj-y += a.o b.o\n",
		"lib/a.c":      "", "lib/part.c": "",
		"lib/b.c": "#include \"other.c\"\n", "lib/other.c": "",
	}), Options{Arch: "x86", Includes: inc})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, r, map[string]string{"lib/part.c": "CONFIG_X", "lib/other.c": ""})
}

// The modules a Rust crate declares are built with it: mod NAME; names
// NAME.rs or NAME/mod.rs beside a crate root, lib.rs or mod.rs, and under
// foo/ for foo.rs, or the file of its #[path] attribute. #[cfg] attributes
// add their condition. Only declarations at the start of a line count, as
// rustfmt puts module-level items there.
func TestRustModules(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                "drivers-y += drivers/\ncore-y += rust/\n",
		"drivers/Makefile":        "obj-$(CONFIG_BINDER) += binder/\n",
		"drivers/binder/Makefile": "obj-y += binder.o\nbinder-y := main.o\n",
		"drivers/binder/main.rs": `
//! The crate root.
//!
//! # #[path = "../example.rs"] mod example;
mod node;
#[macro_use]
/// Docs.
pub(crate) mod range;
mod inline {
    mod nested;
}
`,
		"drivers/binder/node.rs":          "mod wrapper;\n#[path = \"freeze.rs\"]\nmod freeze;\n",
		"drivers/binder/node/wrapper.rs":  "",
		"drivers/binder/freeze.rs":        "",
		"drivers/binder/range/mod.rs":     "mod tree;\n",
		"drivers/binder/range/tree.rs":    "",
		"drivers/binder/inline/nested.rs": "",
		"drivers/binder/nested.rs":        "",
		"drivers/example.rs":              "",
		"rust/Makefile":                   "obj-$(CONFIG_RUST) += kernel.o\n$(obj)/kernel.o: $(src)/kernel/lib.rs FORCE\n\t$(call rustc)\n",
		"rust/kernel/lib.rs": `
#[cfg(CONFIG_X)]
pub mod x;
#[cfg(not(CONFIG_Y))] pub mod y;
#[cfg(all(CONFIG_Z = "y", any(CONFIG_A, CONFIG_B = "m"),))]
mod z;
#[cfg(test)]
mod t;
#[cfg(MODULE)]
mod m;
#[cfg(
    CONFIG_W
)]
mod w;
`,
		"rust/kernel/x.rs": "", "rust/kernel/y.rs": "", "rust/kernel/z/mod.rs": "",
		"rust/kernel/t.rs": "", "rust/kernel/m.rs": "", "rust/kernel/w.rs": "",
	})
	expect(t, r, map[string]string{
		"drivers/binder/node.rs":          "CONFIG_BINDER=y",
		"drivers/binder/node/wrapper.rs":  "CONFIG_BINDER=y",
		"drivers/binder/freeze.rs":        "CONFIG_BINDER=y",
		"drivers/binder/range/mod.rs":     "CONFIG_BINDER=y",
		"drivers/binder/range/tree.rs":    "CONFIG_BINDER=y",
		"drivers/binder/inline/nested.rs": "",
		"drivers/binder/nested.rs":        "",
		"drivers/example.rs":              "",
		"rust/kernel/x.rs":                "CONFIG_RUST && CONFIG_X",
		"rust/kernel/y.rs":                "CONFIG_RUST && !CONFIG_Y",
		"rust/kernel/z/mod.rs":            "(CONFIG_A || CONFIG_B=m) && CONFIG_RUST && CONFIG_Z=y",
		"rust/kernel/t.rs":                "false",
		"rust/kernel/m.rs":                `"defined(MODULE)" && CONFIG_RUST`,
		"rust/kernel/w.rs":                "CONFIG_RUST && CONFIG_W",
	})
}

// grepTree is a tree whose Grep finds only the files listed in found and,
// for Rust files, in rust.
type grepTree struct {
	fs.FS
	found, rust []string
}

func (g grepTree) Grep(strs []string, globs ...string) ([]string, error) {
	switch {
	case slices.Equal(strs, []string{`.c"`, `.S"`}) && slices.Equal(globs, []string{"*.c", "*.S"}):
		return g.found, nil
	case slices.Equal(strs, []string{"mod "}) && slices.Equal(globs, []string{"*.rs"}):
		return g.rust, nil
	}
	return nil, fs.ErrInvalid
}

func (g grepTree) GrepLines(strs []string, globs ...string) (map[string][]string, error) {
	out := map[string][]string{}
	err := fs.WalkDir(g.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !slices.ContainsFunc(globs, func(g string) bool { ok, _ := path.Match(g, path.Base(p)); return ok }) {
			return err
		}
		data, err := fs.ReadFile(g.FS, p)
		for _, l := range strings.Split(string(data), "\n") {
			if slices.ContainsFunc(strs, func(s string) bool { return strings.Contains(l, s) }) {
				out[p] = append(out[p], l)
			}
		}
		return err
	})
	return out, err
}

// The directive lines a GrepFS lists give the #include lines and their
// conditions a read of each file would: past a comment the grep's lines
// leave open, an #else after a tab, a guard after comment lines that
// mention #include, a guard with a comment, and a continuation followed
// by spaces.
func TestListIncludesGrep(t *testing.T) {
	files := map[string]string{
		"a.c": "#include <a1.h> /* first,\n   second */\n#include <a2.h>\n",
		"b.c": "#ifdef CONFIG_X\n#include <b1.h>\n#\telse\n#include <b2.h>\n#endif\n",
		"c.h": "/*\n * Do not #include this directly.\n */\n#ifndef _C_H\n#define _C_H\n#include <c1.h>\n#endif\n",
		"d.h": "#ifndef _D_H /* guard */\n#define _D_H\n#include <d1.h>\n#endif\n",
		"e.c": "#if defined(CONFIG_A) || \\  \n    defined(CONFIG_B)\n#include <e1.h>\n#endif\n",
	}
	fsys := grepTree{FS: tree(files)}
	list, err := listIncludes(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for p, data := range files {
		read, err := list.lines(fsys, p)
		if err != nil {
			t.Fatal(err)
		}
		var got, want []string
		for _, l := range read {
			got = append(got, l.name+" "+l.cond.String())
		}
		for _, l := range incLines([]byte(data), p) {
			want = append(want, l.name+" "+l.cond.String())
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

// ScanIncludes reads only the files a GrepFS finds.
func TestScanIncludesGrep(t *testing.T) {
	fsys := grepTree{FS: tree(map[string]string{
		"a.c": "#include \"x.c\"\n", "b.S": "#include \"y.S\"\n", "c.c": "#include \"x.c\"\n",
		"x.c": "", "y.S": "", "lib.rs": "mod m;\n", "other.rs": "mod n;\n", "m.rs": "", "n.rs": "",
	}), found: []string{"a.c", "b.S"}, rust: []string{"lib.rs"}}
	inc, err := ScanIncludes(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if got := inc.Targets; len(got) != 3 || len(got["x.c"]) != 1 || got["x.c"][0].From != "a.c" || len(got["y.S"]) != 1 || len(got["m.rs"]) != 1 {
		t.Errorf("ScanIncludes = %v, want x.c from a.c, y.S from b.S and m.rs from lib.rs", inc)
	}
}

// An #include in code compiled as 16-bit code on x86-64 takes the mixed
// reading of the arch macros around it; one in kernel code the exact one.
func TestIncludeArchMacros(t *testing.T) {
	inc, err := ScanIncludes(tree(map[string]string{
		"arch/x86/realmode/rm/a.S": "#ifdef __i386__\n#include \"b.S\"\n#endif\n",
		"kernel/c.c":               "#ifdef __i386__\n#include \"d.c\"\n#endif\n",
		"arch/x86/realmode/rm/b.S": "", "kernel/d.c": "",
	}))
	if err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]string{
		"arch/x86/realmode/rm/b.S": `("defined(__i386__)" && CONFIG_X86_64) || CONFIG_X86_32`,
		"kernel/d.c":               "CONFIG_X86_32",
	} {
		if got := inc.Targets[f]; len(got) != 1 || got[0].Cond.String() != want {
			t.Errorf("Includes[%s] = %v, want %s", f, got, want)
		}
	}
}

// A name an #include finds neither next to the including file nor above it
// is looked up in the -I directories of the file's object: libstub
// compiles zboot-decompress-gzip.c with -I$(srctree)/lib/zlib_inflate.
// subdir-ccflags-y reaches the directories below.
func TestIncludeFlags(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                             "drivers-y := drivers/\n",
		"drivers/Makefile":                     "obj-y += stub/ d/\n",
		"drivers/stub/Makefile":                "lib-$(CONFIG_ZBOOT) += zboot-decompress-gzip.o\nCFLAGS_zboot-decompress-gzip.o += -I$(srctree)/lib/zlib_inflate\n",
		"drivers/stub/zboot-decompress-gzip.c": "#include \"inflate.c\"\n",
		"lib/zlib_inflate/inflate.c":           "",
		"drivers/d/Makefile":                   "obj-y += a.o child/\nccflags-$(CONFIG_F) += -I $(src)/sub\nsubdir-ccflags-y += -I$(srctree)/inc\n",
		"drivers/d/a.c":                        "#include \"part.c\"\n",
		"drivers/d/sub/part.c":                 "",
		"drivers/d/child/Makefile":             "obj-y += b.o\n",
		"drivers/d/child/b.c":                  "#include \"shared.c\"\n#include \"generated.c\"\n",
		"inc/shared.c":                         "",
	})
	expect(t, r, map[string]string{
		"lib/zlib_inflate/inflate.c": "CONFIG_ZBOOT",
		"drivers/d/sub/part.c":       "CONFIG_F=y",
		"inc/shared.c":               "true",
	})
}

// A source compiled with -include of a .c or .S file compiles that file
// too, as the arm64 vDSO does with lib/vdso/gettimeofday.c.
func TestForcedIncludes(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":           "drivers-y := drivers/\n",
		"drivers/Makefile":   "obj-y += d/\n",
		"drivers/d/Makefile": "obj-$(CONFIG_V) += vgtod.o\nCFLAGS_vgtod.o += -O2 -include $(srctree)/lib/vdso/gettimeofday.c -include $(src)/env.h\n",
		"drivers/d/vgtod.c":  "", "drivers/d/env.h": "",
		"lib/vdso/gettimeofday.c": "",
	})
	expect(t, r, map[string]string{"lib/vdso/gettimeofday.c": "CONFIG_V"})
}

// asmHeaders is the part of scripts/Makefile.asm-headers (v6.11) that
// decides the wrappers, and kbuildInclude the line of scripts/Kbuild.include
// it takes the arch's list from.
const (
	asmHeaders = `src := $(srctree)/$(subst /generated,,$(obj))
include $(srctree)/scripts/Kbuild.include
-include $(kbuild-file)
ifneq ($(SRCARCH),um)
include $(srctree)/$(generic)/Kbuild
endif
mandatory-y := $(filter-out $(generated-y), $(mandatory-y))
generic-y   += $(foreach f, $(mandatory-y), $(if $(wildcard $(src)/$(f)),,$(f)))
generic-y   := $(addprefix $(obj)/, $(generic-y))
`
	kbuildInclude = "kbuild-file = $(or $(wildcard $(src)/Kbuild),$(src)/Makefile)\n"
)

// The asm-generic wrappers are those the tree's script generates, by the
// rules of its version: the arch's generic-y; since v5.0 also the
// mandatory-y headers the arch has no file for, less its generated-y, read
// through the arch's include of Kbuild.asm in v5.0 and from the generic
// Kbuild since v5.4; before v5.0, with src passed by the caller, no
// fallback.
func TestWrappers(t *testing.T) {
	base := map[string]string{
		"Makefile":                            "# the script runs for include/generated/uapi/asm too\n",
		"arch/x86/include/asm/Kbuild":         "generic-y += gen.h\ngenerated-y += made.h\n",
		"arch/x86/include/asm/own.h":          "",
		"arch/x86/include/uapi/asm/Kbuild":    "include include/uapi/asm-generic/Kbuild.asm\n",
		"include/uapi/asm-generic/Kbuild.asm": "mandatory-y += poll.h\n",
		"include/asm-generic/Kbuild":          "mandatory-y += man.h own.h made.h\n",
	}
	for _, tc := range []struct {
		version   string
		scripts   map[string]string
		asm, uapi string
	}{
		{"v4.19", map[string]string{"scripts/Makefile.asm-generic": "kbuild-file := $(srctree)/arch/$(SRCARCH)/include/$(src)/Kbuild\n-include $(kbuild-file)\nall: $(patsubst %, $(obj)/%, $(generic-y))\n"},
			"gen.h", ""},
		{"v5.0", map[string]string{"scripts/Makefile.asm-generic": `src := $(subst /generated,,$(obj))
-include $(src)/Kbuild
mandatory-y := $(filter-out $(generated-y), $(mandatory-y))
generic-y   += $(foreach f, $(mandatory-y), $(if $(wildcard $(srctree)/$(src)/$(f)),,$(f)))
generic-y   := $(addprefix $(obj)/, $(generic-y))
`}, "gen.h", "poll.h"},
		{"v6.11", map[string]string{"scripts/Makefile.asm-headers": asmHeaders, "scripts/Kbuild.include": kbuildInclude}, "gen.h man.h", "poll.h"},
	} {
		files := maps.Clone(base)
		maps.Copy(files, tc.scripts)
		fsys := tree(files)
		for dir, want := range map[string]string{"asm": tc.asm, "uapi/asm": tc.uapi} {
			if got := strings.Join(slices.Sorted(maps.Keys(wrapped(fsys, "x86", dir))), " "); got != want {
				t.Errorf("%s: wrapped(%s) = %q, want %q", tc.version, dir, got, want)
			}
		}
	}
}

// A header is built where the files including it are, under the condition
// of each directive's line, through other headers and -I directories, a
// bracketed name through the build's include directories and the
// asm-generic wrappers, and an -include flag's header by the object's
// source or, for LINUXINCLUDE's, by every one; a file the build never
// compiles or no Makefile lists adds nothing, and the header is unlisted
// when no listed file includes it.
func TestHeaders(t *testing.T) {
	files := map[string]string{
		"Makefile":             "LINUXINCLUDE := -I$(srctree)/include -include $(srctree)/include/linux/kconfig.h\ndrivers-y := drivers/\n",
		"drivers/Makefile":     "obj-$(CONFIG_FOO) += foo/\nobj-y += core.o\n",
		"drivers/core.c":       "",
		"drivers/foo/Makefile": "obj-y += a.o s.o\nobj-$(CONFIG_FOO_B) += b.o\nobj-$(CONFIG_FOO_M) += m.o\nccflags-y := -I $(src)/include\n",
		"drivers/foo/a.c":      "#include \"foo.h\"\n#include <bar.h>\n#include \"x.h\"\n#include <linux/pub.h>\n#include <asm/gen.h>\n#include <asm/own.h>\n#include <asm/asmh.h>\n",
		"drivers/foo/b.c":      "#ifdef CONFIG_FOO_X\n#include \"foo.h\"\n#include <linux/u.h>\n#endif\n",
		"drivers/foo/m.c":      "#include \"mod.h\"\n#include <asm/man.h>\n",
		"drivers/foo/s.S":      "#include <asm/asmh.h>\n#include <asm/sonly.h>\n",
		// foo.h includes sub.h; x.h and y.h include each other.
		"drivers/foo/foo.h": "#include \"sub/sub.h\"\n", "drivers/foo/sub/sub.h": "",
		"drivers/foo/x.h": "#include \"y.h\"\n", "drivers/foo/y.h": "#include \"x.h\"\n",
		"drivers/foo/include/bar.h": "", "drivers/foo/mod.h": "",
		// Nothing includes orphan.h, a file the build never compiles
		// includes tools.h, an unlisted source odd.h.
		"drivers/foo/orphan.h": "",
		"drivers/foo/tools.h":  "", "tools/t.c": "#include \"../drivers/foo/tools.h\"\n",
		"drivers/foo/odd.h": "", "drivers/foo/unlisted.c": "#include \"odd.h\"\n#include \"foo.h\"\n",
		// Public headers: pub.h includes pub2.h; gen.h is generic-y, man.h
		// mandatory-y without an x86 header, own.h mandatory-y shadowed by
		// x86's own; u.h is uapi; asmh.h includes conly.h for C units
		// only; sonly.h is included by assembly only, so the conly2.h it
		// includes for C units is never compiled; kconfig.h comes from
		// LINUXINCLUDE.
		"include/linux/pub.h": "#include <linux/pub2.h>\n", "include/linux/pub2.h": "",
		"include/linux/kconfig.h":      "",
		"arch/x86/include/asm/Kbuild":  "generic-y += gen.h\n",
		"include/asm-generic/Kbuild":   "mandatory-y += man.h own.h\n",
		"scripts/Makefile.asm-headers": asmHeaders, "scripts/Kbuild.include": kbuildInclude,
		"include/asm-generic/gen.h": "", "include/asm-generic/man.h": "", "include/asm-generic/own.h": "",
		"arch/x86/include/asm/own.h":   "",
		"include/uapi/linux/u.h":       "",
		"arch/x86/include/asm/asmh.h":  "#ifndef __ASSEMBLY__\n#include <linux/conly.h>\n#endif\n",
		"include/linux/conly.h":        "",
		"arch/x86/include/asm/sonly.h": "#ifndef __ASSEMBLY__\n#include <linux/conly2.h>\n#endif\n",
		"include/linux/conly2.h":       "",
	}
	// The crawl lists the #include lines when a header is to be looked
	// up, and only then.
	for _, lookups := range [][]string{{"drivers/foo/foo.h"}, {"include/linux/pub.h", "drivers/foo/a.c"}, {"drivers/foo/a.c"}, nil} {
		r, err := Crawl(tree(files), Options{Arch: "x86", Lookups: lookups})
		if err != nil {
			t.Fatal(err)
		}
		if listed, want := r.Includes.listed != nil, lookups != nil && lookups[0] != "drivers/foo/a.c"; listed != want {
			t.Errorf("Crawl with Lookups %q listed the #include lines: %v, want %v", lookups, listed, want)
		}
	}
	r := crawl(t, files)
	expect(t, r, map[string]string{
		"drivers/foo/foo.h":            "(CONFIG_FOO && CONFIG_FOO_B=m && CONFIG_FOO_X=y) || CONFIG_FOO=y",
		"drivers/foo/sub/sub.h":        "(CONFIG_FOO && CONFIG_FOO_B=m && CONFIG_FOO_X=y) || CONFIG_FOO=y",
		"drivers/foo/include/bar.h":    "CONFIG_FOO=y",
		"drivers/foo/x.h":              "CONFIG_FOO=y",
		"drivers/foo/y.h":              "CONFIG_FOO=y",
		"drivers/foo/mod.h":            "CONFIG_FOO && (CONFIG_FOO=y || CONFIG_FOO_M=m) && CONFIG_FOO_M",
		"include/linux/pub.h":          "CONFIG_FOO=y",
		"include/linux/pub2.h":         "CONFIG_FOO=y",
		"include/asm-generic/gen.h":    "CONFIG_FOO=y",
		"include/asm-generic/man.h":    "CONFIG_FOO && (CONFIG_FOO=y || CONFIG_FOO_M=m) && CONFIG_FOO_M",
		"arch/x86/include/asm/own.h":   "CONFIG_FOO=y",
		"include/uapi/linux/u.h":       "CONFIG_FOO && (CONFIG_FOO=y || CONFIG_FOO_B=m) && CONFIG_FOO_B && CONFIG_FOO_X=y",
		"arch/x86/include/asm/asmh.h":  "CONFIG_FOO=y",
		"include/linux/conly.h":        "CONFIG_FOO=y",
		"arch/x86/include/asm/sonly.h": "CONFIG_FOO=y",
		"include/linux/conly2.h":       "false",
		"include/linux/kconfig.h":      "true",
	})
	for _, p := range []string{"drivers/foo/orphan.h", "drivers/foo/tools.h", "drivers/foo/odd.h", "include/asm-generic/own.h"} {
		if _, st := r.Lookup(p); st != Unlisted {
			t.Errorf("%s: %v, want Unlisted", p, st)
		}
	}
	// A header is built into a module where the sources including it are.
	builtin, module := r.Module("drivers/foo/mod.h")
	if got := builtin.String() + " / " + module.String(); got != "CONFIG_FOO=y && CONFIG_FOO_M=y / CONFIG_FOO && CONFIG_FOO_M=m" {
		t.Errorf("Module(mod.h) = %s", got)
	}
}
