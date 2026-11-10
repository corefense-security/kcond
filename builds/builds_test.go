package builds

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/kbuild"
)

// archTree is a kernel with x86, arm64 and s390: drivers for one SoC
// family, wireless that s390 lacks, a symbol x86 forces on, and code built
// by rules the crawl does not follow.
func archTree() fstest.MapFS {
	files := map[string]string{
		"Makefile": "include $(srctree)/arch/$(SRCARCH)/Makefile\ndrivers-y += drivers/\n",
		"Kconfig":  "config MODULES\n\tbool \"modules\"\n\tmodules\n\nsource \"arch/$(SRCARCH)/Kconfig\"\nsource \"drivers/Kconfig\"\n",

		"arch/x86/Makefile":            "core-y += arch/x86/kernel/\n",
		"arch/x86/kernel/Makefile":     "obj-y += entry_$(BITS).o setup.o\n",
		"arch/x86/entry/vdso/Makefile": "vobjs-y += vclock.o\n",
		"arch/x86/Kconfig": `
config X86
	def_bool y
	select FORCED

config 64BIT
	bool "64-bit kernel" if "$(ARCH)" = "x86"
	default "$(ARCH)" != "i386"
`,
		"arch/arm64/Makefile":        "core-y += arch/arm64/kernel/\n",
		"arch/arm64/kernel/Makefile": "obj-y += cpu.o\n",
		"arch/arm64/Kconfig": `
config ARM64
	def_bool y

config ARCH_QCOM
	bool "Qualcomm"

choice
	prompt "Page size"

config ARM64_4K_PAGES
	bool "4KB"

config ARM64_64K_PAGES
	bool "64KB"

endchoice
`,
		"arch/s390/Makefile":        "core-y += arch/s390/kernel/\n",
		"arch/s390/kernel/Makefile": "obj-y += setup.o\n",
		"arch/s390/Kconfig":         "config S390\n\tdef_bool y\n",

		"drivers/Makefile": "obj-y += core.o page.o\nobj-$(CONFIG_MSM) += msm.o\nobj-$(CONFIG_WIFI) += wifi.o\n" +
			"obj-$(CONFIG_FORCED) += forced.o\nobj-$(CONFIG_NEW) += new.o\nobj-$(CONFIG_DEAD) += dead.o\nobj-$(CONFIG_ARCH_QCOM) += qcom.o\n",
		"drivers/msm.c": "#include \"msm.h\"\n",
		"drivers/Kconfig": `
config COMPILE_TEST
	bool "Compile also drivers which will not load"

config MSM
	tristate "MSM"
	depends on ARCH_QCOM || COMPILE_TEST

config WIFI
	tristate "Wireless"
	depends on !S390

config WIFI_USB
	tristate "USB wireless"
	depends on WIFI

config WIFI_LEDS
	bool "Wireless LEDs"
	depends on WIFI

config WIFI_DRIVER
	tristate "A wireless driver"
	depends on X86
	select WIFI

config WIFI_LED_DRIVER
	tristate "A wireless LED driver"
	depends on WIFI_LEDS

config WIFI_USB_LEDS
	tristate "LEDs of USB wireless devices"
	depends on WIFI && WIFI_LEDS

config WIFI_PLATFORM
	bool "Platform wireless devices"
	depends on X86

config WIFI_PLATFORM_DRIVER
	tristate "A platform wireless driver"
	depends on WIFI && WIFI_PLATFORM

config FORCED
	bool

config DEAD
	bool "Only for build tests"
	depends on COMPILE_TEST
`,
	}
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(strings.TrimLeft(content, "\n"))}
	}
	for _, src := range []string{"arch/x86/kernel/entry_32.S", "arch/x86/kernel/entry_64.S", "arch/x86/kernel/setup.c",
		"arch/x86/entry/vdso/vclock.c", "arch/arm64/kernel/cpu.c", "arch/s390/kernel/setup.c", "arch/mips/kernel/setup.c",
		"drivers/core.c", "drivers/page.c", "drivers/msm.h", "drivers/wifi.c", "drivers/forced.c", "drivers/new.c",
		"drivers/dead.c", "drivers/qcom.c", "include/linux/wifi.h"} {
		fsys[src] = &fstest.MapFile{}
	}
	return fsys
}

// analyzeFiles runs every build of the tree over the given changed files,
// keyed by path with their region.
func analyzeFiles(t *testing.T, fsys fstest.MapFS, regions map[string]string) map[string]*FileArches {
	t.Helper()
	out := map[string]*FileArches{}
	conds := map[string]*kcond.Expr{}
	for p, r := range regions {
		e, err := kcond.Parse(r)
		if err != nil {
			t.Fatal(err)
		}
		conds[p] = e
		out[p] = &FileArches{Path: p, Header: strings.HasSuffix(p, ".h")}
	}
	var builds, names []string
	err := Each(fsys, nil, nil, func(b Build) error {
		builds = append(builds, b.Arch)
		names = append(names, b.Name)
		for p, f := range out {
			f.Add(b, conds[p])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"x86", "x86", "arm64", "s390"}; !slices.Equal(builds, want) {
		t.Errorf("builds = %v, want %v", builds, want)
	}
	if want := []string{"x86_64", "i386", "arm64", "s390"}; !slices.Equal(names, want) {
		t.Errorf("build names = %v, want %v", names, want)
	}
	return out
}

func TestBuildCond(t *testing.T) {
	region := kcond.Const(true)
	paths := []string{"drivers/msm.c", "drivers/msm.h", "drivers/qcom.c", "arch/arm64/kernel/cpu.c", "arch/x86/kernel/entry_32.S", "arch/mips/kernel/setup.c", "include/linux/wifi.h"}
	got := map[string]map[string]string{}
	err := Each(archTree(), nil, nil, func(b Build) error {
		for _, p := range paths {
			fc := BuildCond(p, strings.HasSuffix(p, ".h"), region, b)
			s := fc.Status
			if fc.Kbuild != nil {
				s += " " + fc.Kbuild.String()
			}
			if got[p] == nil {
				got[p] = map[string]string{}
			}
			got[p][b.Name] = s
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		// Kbuild lists the driver everywhere; whether MSM can be on is a
		// Kconfig matter the arch labels settle.
		"drivers/msm.c": {"x86_64": "built CONFIG_MSM", "i386": "built CONFIG_MSM", "arm64": "built CONFIG_MSM", "s390": "built CONFIG_MSM"},
		// A header is built where the sources including it are; a public
		// one has no includers to follow.
		"drivers/msm.h": {"x86_64": "built CONFIG_MSM", "i386": "built CONFIG_MSM", "arm64": "built CONFIG_MSM", "s390": "built CONFIG_MSM"},
		// A symbol only arm64's Kconfig defines is off in the other builds.
		"drivers/qcom.c":             {"x86_64": "not built", "i386": "not built", "arm64": "built CONFIG_ARCH_QCOM", "s390": "not built"},
		"arch/arm64/kernel/cpu.c":    {"x86_64": "not built", "i386": "not built", "arm64": "built true", "s390": "not built"},
		"arch/x86/kernel/entry_32.S": {"x86_64": "not built", "i386": "built true", "arm64": "not built", "s390": "not built"},
		"arch/mips/kernel/setup.c":   {"x86_64": "not built", "i386": "not built", "arm64": "not built", "s390": "not built"},
		"include/linux/wifi.h":       {"x86_64": "header", "i386": "header", "arm64": "header", "s390": "header"},
	}
	for p, w := range want {
		for name, s := range w {
			if got[p][name] != s {
				t.Errorf("%s in %s: %q, want %q", p, name, got[p][name], s)
			}
		}
	}
	// A build whose crawl failed knows nothing but the arch directories.
	failed := Build{Arch: "riscv", Name: "riscv"}
	if fc := BuildCond("drivers/core.c", false, region, failed); fc.Status != StatusUnlisted || fc.Kbuild != nil {
		t.Errorf("failed build, generic file: %+v", fc)
	}
	if fc := BuildCond("arch/arm64/kernel/cpu.c", false, region, failed); fc.Status != StatusNotBuilt {
		t.Errorf("failed build, other arch's file: %+v", fc)
	}
}

func TestFileArches(t *testing.T) {
	files := analyzeFiles(t, archTree(), map[string]string{
		"drivers/core.c": "true", "drivers/msm.c": "true", "drivers/wifi.c": "true", "drivers/forced.c": "true",
		"drivers/new.c": "true", "drivers/dead.c": "true", "arch/x86/kernel/entry_32.S": "true",
		"arch/x86/entry/vdso/vclock.c": "true", "arch/arm64/kernel/cpu.c": "true", "arch/mips/kernel/setup.c": "true",
		"include/linux/wifi.h": "CONFIG_WIFI",
		"drivers/page.c":       `"PAGE_SIZE < 8192"`, "include/linux/big.h": `"PAGE_SIZE > 4096"`,
	})
	for _, tc := range []struct {
		path, arches, unknown, always string
	}{
		{"drivers/core.c", "x86,arm64,s390", "", "x86,arm64,s390"},
		// COMPILE_TEST is off: a Qualcomm driver builds on arm64 only.
		{"drivers/msm.c", "arm64", "", ""},
		{"drivers/wifi.c", "x86,arm64", "", ""},
		// X86 selects FORCED, so the file is in every x86-64 build.
		{"drivers/forced.c", "x86", "", "x86"},
		// NEW is defined by no Kconfig file, most likely added by the fix.
		{"drivers/new.c", "x86,arm64,s390", "", ""},
		{"drivers/dead.c", "", "", ""},
		// Only the i386 build lists the _32 file, and it does not decide.
		{"arch/x86/kernel/entry_32.S", "x86", "", ""},
		{"arch/x86/entry/vdso/vclock.c", "x86", "x86", ""},
		{"arch/arm64/kernel/cpu.c", "arm64", "", "arm64"},
		{"arch/mips/kernel/setup.c", "", "", ""},
		{"include/linux/wifi.h", "x86,arm64", "", ""},
		// x86 and s390 have 4 KiB pages, arm64 a choice.
		{"drivers/page.c", "x86,arm64,s390", "", "x86,s390"},
		// A header whose changed lines no unit compiles is not built.
		{"include/linux/big.h", "arm64", "", ""},
	} {
		f := files[tc.path]
		arches, unknown := f.Lists()
		if got := strings.Join(arches, ","); got != tc.arches {
			t.Errorf("%s: arches %q, want %q", tc.path, got, tc.arches)
		}
		if got := strings.Join(unknown, ","); got != tc.unknown {
			t.Errorf("%s: unknown %q, want %q", tc.path, got, tc.unknown)
		}
		if got := strings.Join(f.Always, ","); got != tc.always {
			t.Errorf("%s: always %q, want %q", tc.path, got, tc.always)
		}
		if !slices.Equal(f.Present, []string{"x86", "arm64", "s390"}) {
			t.Errorf("%s: present %v", tc.path, f.Present)
		}
	}
}

func TestSummarize(t *testing.T) {
	files := analyzeFiles(t, archTree(), map[string]string{
		"drivers/core.c": "true", "drivers/msm.c": "true", "drivers/wifi.c": "true", "drivers/forced.c": "true",
		"drivers/dead.c": "true", "arch/x86/entry/vdso/vclock.c": "true", "arch/mips/kernel/setup.c": "true",
		"arch/s390/kernel/setup.c": "true", "include/linux/wifi.h": "true",
	})
	sum := func(paths ...string) ArchSummary {
		var fs []FileArches
		for _, p := range paths {
			if f, ok := files[p]; ok {
				fs = append(fs, *f)
			} else {
				fs = append(fs, FileArches{Path: p})
			}
		}
		return Summarize(fs)
	}
	for _, tc := range []struct {
		name   string
		s      ArchSummary
		arches string
		label  string
		always string
		unsure bool
	}{
		{"generic and always", sum("drivers/core.c"), "x86,arm64,s390", "generic", "x86,arm64,s390", false},
		// s390 is not needed for generic.
		{"no s390", sum("drivers/wifi.c"), "x86,arm64", "generic", "", false},
		{"one arch", sum("drivers/msm.c"), "arm64", "arm64", "", false},
		{"several", sum("drivers/forced.c", "arch/s390/kernel/setup.c"), "x86,s390", "several", "x86,s390", false},
		{"always on one of two", sum("drivers/forced.c", "drivers/msm.c"), "x86,arm64", "generic", "x86", false},
		// Headers count only when no source changed.
		{"header ignored", sum("drivers/msm.c", "include/linux/wifi.h"), "arm64", "arm64", "", false},
		{"header only", sum("include/linux/wifi.h"), "x86,arm64,s390", "generic", "", true},
		{"special rules", sum("arch/x86/entry/vdso/vclock.c"), "x86", "x86", "", true},
		{"none", sum("drivers/dead.c"), "", "none", "", false},
		{"other arch", sum("arch/mips/kernel/setup.c"), "", "other", "", false},
		// A header left out next to sources does not make it none.
		{"other arch and header", sum("arch/mips/kernel/setup.c", "include/linux/wifi.h"), "", "other", "", false},
		// A file never found makes the result uncertain.
		{"missing file", sum("drivers/msm.c", "drivers/gone.c"), "arm64", "arm64", "", true},
		{"nothing analysed", sum("drivers/gone.c"), "", "", "", true},
		// A header found does not stand in for the change's sources.
		{"source never found", sum("drivers/gone.c", "include/linux/wifi.h"), "", "", "", true},
		{"no files", sum(), "", "", "", false},
	} {
		got, always := strings.Join(tc.s.Arches, ","), strings.Join(tc.s.Always, ",")
		if got != tc.arches || tc.s.Label != tc.label || always != tc.always || tc.s.Uncertain != tc.unsure {
			t.Errorf("%s: arches %q label %q always %q uncertain %v, want %q %q %q %v",
				tc.name, got, tc.s.Label, always, tc.s.Uncertain, tc.arches, tc.label, tc.always, tc.unsure)
		}
	}
}

// The builds of a tree reuse the #include directives of the x86 crawl, and
// each gives an included file the condition it builds the includer under.
func TestBuildsShareIncludes(t *testing.T) {
	fsys := archTree()
	fsys["drivers/part.c"] = &fstest.MapFile{}
	// No file of the tree includes drivers/part.c: only a build that reuses
	// these directives builds it.
	inc := &kbuild.Includes{Targets: map[string][]kbuild.Include{"drivers/part.c": {{From: "arch/arm64/kernel/cpu.c", Cond: kcond.Const(true)}}}}
	x86, err := kbuild.Crawl(fsys, kbuild.Options{Arch: "x86", Includes: inc})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]kbuild.Status{}
	err = Each(fsys, x86, nil, func(b Build) error {
		_, got[b.Name] = b.Kbuild.Lookup("drivers/part.c")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]kbuild.Status{"x86_64": kbuild.Unlisted, "i386": kbuild.Unlisted, "arm64": kbuild.Built, "s390": kbuild.Unlisted}
	if !maps.Equal(got, want) {
		t.Errorf("drivers/part.c by build = %v, want %v", got, want)
	}
}

func TestFailedBuild(t *testing.T) {
	// A build whose crawl or Kconfig failed knows nothing about the files
	// of its arch, but still rules out other arches' files.
	b := Build{Arch: "riscv"}
	region := kcond.Const(true)
	if v := FileArch("drivers/core.c", false, region, b); v != ArchMaybe {
		t.Errorf("generic file: %v, want maybe", v)
	}
	if v := FileArch("arch/arm64/kernel/cpu.c", false, region, b); v != ArchNo {
		t.Errorf("other arch's file: %v, want no", v)
	}
	x86 := Build{Arch: "x86", X86_64: true, Kbuild: &kbuild.Result{Arch: "x86"}}
	if AlwaysBuilt("drivers/core.c", false, region, x86) {
		t.Error("always built without Kconfig values")
	}
	// Err says why: here the tree has no top-level Makefile.
	noMake := fstest.MapFS{"arch/riscv/Kconfig": {Data: []byte("config RISCV\n\tdef_bool y\n")}}
	if b, ok := Named(noMake, "riscv", nil); !ok || b.Kbuild != nil || !errors.Is(b.Err, kbuild.ErrNoMakefile) {
		t.Errorf("Named without a Makefile = %+v, %v; want Err ErrNoMakefile", b, ok)
	}
	err := Each(noMake, nil, nil, func(b Build) error {
		if !errors.Is(b.Err, kbuild.ErrNoMakefile) || b.Values == nil {
			t.Errorf("Each without a Makefile: %s: Err %v, Values %v", b.Name, b.Err, b.Values)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A build reads a page size comparison by its architecture's page sizes:
// x86 has 4 KiB pages, arm64 and powerpc a choice.
func TestBuildRegion(t *testing.T) {
	region, err := kcond.Parse(`"PAGE_SIZE < 8192" && CONFIG_X`)
	if err != nil {
		t.Fatal(err)
	}
	for arch, want := range map[string]string{
		"x86":     "CONFIG_X",
		"s390":    "CONFIG_X",
		"arm64":   "CONFIG_ARM64_4K_PAGES && CONFIG_X",
		"powerpc": "CONFIG_PPC_4K_PAGES && CONFIG_X",
	} {
		if got := (Build{Arch: arch}).Region("drivers/igb.c", region).String(); got != want {
			t.Errorf("%s: %s, want %s", arch, got, want)
		}
	}
	other, _ := kcond.Parse(`"defined(MODULE)"`)
	if got := (Build{Arch: "x86"}).Region("drivers/igb.c", other); got != other {
		t.Errorf("other atom: %s", got)
	}
}

// A source's lines under #ifndef MODULE are compiled where it is built into
// the kernel: lp.c where PRINTER=y, aha152x.c, compiled on its own and
// #included into the aha152x_cs module, where either is built in; both.c,
// listed in obj-y and obj-m, where obj-y wins. A header follows the
// sources including it; in a public header the atom stays.
func TestRegionModule(t *testing.T) {
	fsys := fstest.MapFS{
		"Makefile": {Data: []byte("drivers-y += drivers/\n")},
		"drivers/Makefile": {Data: []byte("obj-$(CONFIG_PRINTER) += lp.o\nobj-$(CONFIG_S) += aha152x.o\n" +
			"obj-$(CONFIG_PC) += aha152x_cs.o\naha152x_cs-objs := aha152x_core.o\nobj-$(CONFIG_A) += both.o\nobj-$(CONFIG_B) += both.o\n")},
		"drivers/aha152x_core.c": {Data: []byte("#include \"aha152x.c\"\n")},
		"drivers/lp.c":           {Data: []byte("#include \"lp.h\"\n")},
		"drivers/lp.h":           {}, "drivers/aha152x.c": {}, "drivers/both.c": {},
	}
	res, err := kbuild.Crawl(fsys, kbuild.Options{Arch: "x86"})
	if err != nil {
		t.Fatal(err)
	}
	b := Build{Arch: "x86", Name: "x86_64", X86_64: true, Kbuild: res}
	region := p(t, `!"defined(MODULE)"`)
	for path, want := range map[string]string{
		"drivers/lp.c":      "CONFIG_PRINTER=y",
		"drivers/lp.h":      "CONFIG_PRINTER=y",
		"drivers/aha152x.c": "CONFIG_PC=y || CONFIG_S=y",
		"drivers/both.c":    "CONFIG_A=y || CONFIG_B=y",
	} {
		c, unknown := Combine([]FileCond{BuildCond(path, strings.HasSuffix(path, ".h"), region, b)})
		if eq, ok := kcond.Equal(c, p(t, want)); !ok || !eq || unknown {
			t.Errorf("%s: %s (unknown %v), want %s", path, c, unknown, want)
		}
	}
	if fc := BuildCond("include/linux/lp.h", true, region, b); fc.Region.String() != region.String() {
		t.Errorf("header region %s, want %s", fc.Region, region)
	}
}

// A macro a -D flag defines holds where the build compiles the source with
// the flag; elsewhere a header may still define it, so the atom stays.
func TestRegionDefines(t *testing.T) {
	fsys := fstest.MapFS{
		"Makefile":         {Data: []byte("drivers-y += drivers/\n")},
		"drivers/Makefile": {Data: []byte("obj-$(CONFIG_X) += x.o\nccflags-$(CONFIG_X_DEBUG) += -DDEBUG\n")},
		"drivers/x.c":      {},
	}
	res, err := kbuild.Crawl(fsys, kbuild.Options{Arch: "x86"})
	if err != nil {
		t.Fatal(err)
	}
	b := Build{Arch: "x86", Name: "x86_64", X86_64: true, Kbuild: res}
	c, unknown := Combine([]FileCond{BuildCond("drivers/x.c", false, p(t, `"defined(DEBUG)"`), b)})
	if want := p(t, `CONFIG_X && (CONFIG_X_DEBUG=y || "defined(DEBUG)")`); unknown || !equal(c, want) {
		t.Errorf("Combine = %s (unknown %v), want %s", c, unknown, want)
	}
	// Without a flag naming it, the macro's atom stays as it was, and so
	// does an atom that only ends like a defined() test.
	for _, atom := range []string{`"defined(OTHER)"`, `"DEBUG)"`} {
		if fc := BuildCond("drivers/x.c", false, p(t, atom), b); fc.Region.String() != atom {
			t.Errorf("region %s, want %s", fc.Region, atom)
		}
	}
}

func equal(a, b *kcond.Expr) bool {
	eq, ok := kcond.Equal(a, b)
	return ok && eq
}

// A build writes a test of a symbol that cannot be m there plainly: X=y as
// X and X=m as false. Tristates, and symbols its Kconfig lacks, stay.
func TestBuildPlain(t *testing.T) {
	var x86 Build
	if err := Each(archTree(), nil, nil, func(b Build) error {
		if b.X86_64 {
			x86 = b
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"CONFIG_FORCED=y":                  "CONFIG_FORCED",
		"CONFIG_FORCED=m || CONFIG_WIFI":   "CONFIG_WIFI",
		"CONFIG_WIFI=y":                    "CONFIG_WIFI=y",
		"CONFIG_NEW=y":                     "CONFIG_NEW=y",
		"CONFIG_ARCH_QCOM":                 "false",
		"CONFIG_ARCH_QCOM=y || CONFIG_NEW": "CONFIG_NEW",
		`"defined(X)" && CONFIG_FORCED=y`:  `"defined(X)" && CONFIG_FORCED`,
		// A gate Kconfig settles: WIFI_USB depends on WIFI, so WIFI_USB=y
		// needs WIFI=y, and the directory is linked.
		"CONFIG_WIFI && (CONFIG_WIFI=y || CONFIG_WIFI_USB=m) && CONFIG_WIFI_USB":                        "CONFIG_WIFI && CONFIG_WIFI_USB",
		"CONFIG_WIFI && ((CONFIG_WIFI=y && CONFIG_WIFI_USB=y) || CONFIG_WIFI_USB=m) && CONFIG_WIFI_USB": "CONFIG_WIFI && CONFIG_WIFI_USB",
		"CONFIG_WIFI_USB=y && (CONFIG_WIFI=y || CONFIG_WIFI_USB=m)":                                     "CONFIG_WIFI_USB=y",
		// WIFI_DRIVER selects WIFI, so WIFI_DRIVER=y makes WIFI y too.
		"CONFIG_WIFI && (CONFIG_WIFI=y || CONFIG_WIFI_DRIVER=m) && CONFIG_WIFI_DRIVER": "CONFIG_WIFI && CONFIG_WIFI_DRIVER",
		// NEW is not among what WIFI_USB requires; a bool WIFI_LEDS=y
		// does not need WIFI=y; a negation is not proved.
		"CONFIG_NEW && (CONFIG_NEW=y || CONFIG_WIFI_USB=m) && CONFIG_WIFI_USB":     "CONFIG_NEW && (CONFIG_NEW=y || CONFIG_WIFI_USB=m) && CONFIG_WIFI_USB",
		"CONFIG_WIFI && (CONFIG_WIFI=y || CONFIG_WIFI_LEDS=m) && CONFIG_WIFI_LEDS": "CONFIG_WIFI=y && CONFIG_WIFI_LEDS",
		"CONFIG_WIFI && (!CONFIG_FORCED || CONFIG_WIFI_USB=m) && CONFIG_WIFI_USB":  "(!CONFIG_FORCED || CONFIG_WIFI_USB=m) && CONFIG_WIFI && CONFIG_WIFI_USB",
		// WIFI_LED_DRIVER=y needs only WIFI_LEDS=y, a bool WIFI=m lets be y;
		// WIFI_USB_LEDS depends on WIFI itself, as well as on WIFI_LEDS;
		// WIFI_PLATFORM_DRIVER=y has the bool WIFI_PLATFORM=y, and so the
		// bool it requires, X86=y.
		"CONFIG_WIFI && ((CONFIG_WIFI=y && CONFIG_X86) || CONFIG_WIFI_PLATFORM_DRIVER=m) && CONFIG_WIFI_PLATFORM_DRIVER": "CONFIG_WIFI && CONFIG_WIFI_PLATFORM_DRIVER",
		"CONFIG_WIFI && (CONFIG_WIFI=y || CONFIG_WIFI_USB_LEDS=m) && CONFIG_WIFI_USB_LEDS":                               "CONFIG_WIFI && CONFIG_WIFI_USB_LEDS",
		"CONFIG_WIFI && (CONFIG_WIFI=y || CONFIG_WIFI_LED_DRIVER=m) && CONFIG_WIFI_LED_DRIVER":                           "CONFIG_WIFI && (CONFIG_WIFI=y || CONFIG_WIFI_LED_DRIVER=m) && CONFIG_WIFI_LED_DRIVER",
		// An OR drops a term on only with another term: WIFI_USB depends
		// on WIFI, WIFI_DRIVER selects it; WIFI=y is not implied, and
		// WIFI_LEDS and WIFI_USB imply nothing of each other.
		"CONFIG_WIFI || CONFIG_WIFI_USB":                    "CONFIG_WIFI",
		"CONFIG_WIFI || (CONFIG_FORCED && CONFIG_WIFI_USB)": "CONFIG_WIFI",
		"CONFIG_WIFI || CONFIG_WIFI_USB=m":                  "CONFIG_WIFI",
		"CONFIG_WIFI || CONFIG_WIFI_DRIVER":                 "CONFIG_WIFI",
		"CONFIG_NEW && (CONFIG_WIFI || CONFIG_WIFI_USB)":    "CONFIG_NEW && CONFIG_WIFI",
		"CONFIG_WIFI=y || CONFIG_WIFI_USB":                  "CONFIG_WIFI=y || CONFIG_WIFI_USB",
		"CONFIG_WIFI_LEDS || CONFIG_WIFI_USB":               "CONFIG_WIFI_LEDS || CONFIG_WIFI_USB",
	} {
		if got := x86.Plain(p(t, in)).String(); got != want {
			t.Errorf("Plain(%s) = %s, want %s", in, got, want)
		}
	}
	if got := (Build{}).Plain(p(t, "CONFIG_FORCED=y")).String(); got != "CONFIG_FORCED=y" {
		t.Errorf("without Kconfig: %s", got)
	}
}

// A build reads its Kconfig beside its crawl, for Build.Plain.
func TestBuildValues(t *testing.T) {
	if sp, ok := specOf(archTree(), X86_64Build); !ok {
		t.Fatal("x86_64: no build")
	} else if v, err := sp.values(archTree()); v == nil {
		t.Fatalf("x86_64: no values: %v", err)
	} else if m, ok := v.Modular("CONFIG_WIFI"); !m || !ok {
		t.Errorf("x86_64 WIFI: modular %v, known %v", m, ok)
	}
	if sp, ok := specOf(archTree(), "riscv"); ok {
		t.Errorf("riscv, which the tree lacks: %+v", sp)
	}
}
