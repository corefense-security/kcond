package kbuild

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/corefense-security/kcond"
)

// tree builds an in-memory kernel tree. Files listed only by name (empty
// content) stand for sources.
func tree(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(strings.TrimLeft(content, "\n"))}
	}
	return fsys
}

func crawl(t *testing.T, files map[string]string) *Result {
	t.Helper()
	r, err := Crawl(tree(files), Options{Arch: "x86"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	return r
}

// expect checks the condition of each file; "" means not built.
func expect(t *testing.T, r *Result, want map[string]string) {
	t.Helper()
	for path, cond := range want {
		e, st := r.Lookup(path)
		switch {
		case cond == "" && st == Built:
			t.Errorf("%s: built under %q, want not built", path, e)
		case cond != "" && st != Built:
			t.Errorf("%s: %v, want %q", path, st, cond)
		case cond != "" && e.String() != cond:
			t.Errorf("%s: %q, want %q", path, e, cond)
		}
	}
}

// A Makefile that appends to MAKEFLAGS must not make make's own flags
// known: v7.2 decides whether to recurse from them.
const subMake = `
MAKEFLAGS += -rR
ifeq ($(filter --no-print-directory, $(MAKEFLAGS)),)
need-sub-make := 1
endif
ifeq ($(need-sub-make),1)
__sub-make:
	$(MAKE) -C $(abs_output)
else
`

func TestRuntimeVariables(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":         subMake + "drivers-y := drivers/\nendif\n",
		"drivers/Makefile": "obj-y += a.o\n",
		"drivers/a.c":      "",
	})
	expect(t, r, map[string]string{"drivers/a.c": "true"})
}

// oldTop is a pre-v6.1 top-level Makefile: directory lists in core-y and
// friends, later rewritten to built-in.o names.
const oldTop = `
init-y		:= init/
drivers-y	:= drivers/ sound/
net-y		:= net/
core-y		:= usr/
include $(srctree)/arch/$(SRCARCH)/Makefile
core-y		+= kernel/ mm/
core-$(CONFIG_BLOCK) += block/
ifeq ($(KBUILD_EXTMOD),)
drivers-$(CONFIG_SAMPLES) += samples/
endif
core-y		:= $(patsubst %/, %/built-in.o, $(core-y))
drivers-y	:= $(patsubst %/, %/built-in.o, $(drivers-y))
vmlinux: FORCE
	@echo obj-y += bogus/
`

func TestOldLayout(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                 oldTop,
		"arch/x86/Makefile":        "core-y += arch/x86/\ndrivers-$(CONFIG_PCI) += arch/x86/pci/\n",
		"arch/x86/Kbuild":          "obj-y += kernel/\n",
		"arch/x86/kernel/Makefile": "obj-y += setup.o\nobj-$(CONFIG_SMP) += smp.o\n",
		"arch/x86/kernel/setup.c":  "",
		"arch/x86/kernel/smp.c":    "",
		"arch/x86/pci/Makefile":    "obj-y += common.o\n",
		"arch/x86/pci/common.c":    "",
		"arch/arm/kernel/setup.c":  "",
		"block/Makefile":           "obj-y += bio.o\n",
		"block/bio.c":              "",
		"kernel/Makefile":          "obj-y += fork.o\n",
		"kernel/fork.c":            "",
		"drivers/Makefile":         "obj-$(CONFIG_NET) += net/\n",
		"drivers/net/Makefile":     "obj-$(CONFIG_FOO) += foo.o\nobj-y += bar.o\n",
		"drivers/net/foo.c":        "",
		"drivers/net/bar.c":        "",
		"samples/Makefile":         "obj-y += sample.o\n",
		"samples/sample.c":         "",
		"bogus/Makefile":           "obj-y += bogus.o\n",
		"bogus/bogus.c":            "",
	})
	expect(t, r, map[string]string{
		"kernel/fork.c": "true",
		"block/bio.c":   "CONFIG_BLOCK",
		// net/ is linked where NET=y; a module is built wherever it is entered.
		"drivers/net/foo.c":       "CONFIG_FOO && (CONFIG_FOO=m || CONFIG_NET=y) && CONFIG_NET",
		"drivers/net/bar.c":       "CONFIG_NET=y",
		"arch/x86/kernel/setup.c": "true",
		"arch/x86/kernel/smp.c":   "CONFIG_SMP",
		"arch/x86/pci/common.c":   "CONFIG_PCI",
		"samples/sample.c":        "CONFIG_SAMPLES",
		"bogus/bogus.c":           "",
	})
	if _, st := r.Lookup("arch/arm/kernel/setup.c"); st != NotBuilt {
		t.Errorf("arch/arm file: %v, want NotBuilt", st)
	}
}

// newTop is the v6.1+ split: directories in the root Kbuild, arch lists
// exported from the top-level Makefile.
func TestNewLayout(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile": `
core-y		:=
drivers-y	:=
libs-y		:= lib/
include $(srctree)/arch/$(SRCARCH)/Makefile
export ARCH_CORE	:= $(core-y)
export ARCH_LIB		:= $(filter %/, $(libs-y))
export ARCH_DRIVERS	:= $(drivers-y) $(drivers-m)
`,
		"Kbuild": `
obj-y			+= init/
obj-y			+= arch/$(SRCARCH)/
obj-y			+= $(ARCH_CORE)
obj-$(CONFIG_NET)	+= net/
obj-y			+= $(ARCH_LIB)
obj-y			+= $(ARCH_DRIVERS)
`,
		"arch/x86/Makefile":        "libs-y += arch/x86/lib/\ndrivers-$(CONFIG_PM) += arch/x86/power/\n",
		"arch/x86/Kbuild":          "obj-$(CONFIG_KVM) += kvm/\n",
		"arch/x86/kvm/Makefile":    "kvm-amd-y += svm/svm.o\nkvm-amd-$(CONFIG_KVM_AMD_SEV) += svm/sev.o\nobj-$(CONFIG_KVM_AMD) += kvm-amd.o\n",
		"arch/x86/kvm/svm/svm.c":   "",
		"arch/x86/kvm/svm/sev.c":   "",
		"arch/x86/lib/Makefile":    "lib-y += memcpy_64.o\n",
		"arch/x86/lib/memcpy_64.S": "",
		"arch/x86/power/Makefile":  "obj-y += cpu.o\n",
		"arch/x86/power/cpu.c":     "",
		"net/Makefile":             "obj-$(CONFIG_INET) += ipv4/\n",
		"net/ipv4/Makefile":        "obj-$(CONFIG_TCP_CONG_BBR) += tcp_bbr.o\n",
		"net/ipv4/tcp_bbr.c":       "",
		"lib/Makefile":             "lib-y += string.o\n",
		"lib/string.c":             "",
	})
	expect(t, r, map[string]string{
		"net/ipv4/tcp_bbr.c":       "CONFIG_INET && ((CONFIG_INET=y && CONFIG_NET=y) || CONFIG_TCP_CONG_BBR=m) && CONFIG_NET && CONFIG_TCP_CONG_BBR",
		"arch/x86/kvm/svm/svm.c":   "CONFIG_KVM && (CONFIG_KVM=y || CONFIG_KVM_AMD=m) && CONFIG_KVM_AMD",
		"arch/x86/kvm/svm/sev.c":   "CONFIG_KVM && (CONFIG_KVM=y || (CONFIG_KVM_AMD=m && CONFIG_KVM_AMD_SEV)) && ((CONFIG_KVM_AMD && CONFIG_KVM_AMD_SEV=y) || (CONFIG_KVM_AMD=m && CONFIG_KVM_AMD_SEV=m))",
		"arch/x86/lib/memcpy_64.S": "true",
		"arch/x86/power/cpu.c":     "CONFIG_PM",
		"lib/string.c":             "true",
	})
}

// dirTree wraps one directory Makefile in a minimal tree.
func dirTree(makefile string, files ...string) map[string]string {
	m := map[string]string{
		"Makefile":           "drivers-y := drivers/\n",
		"drivers/Makefile":   "obj-y += d/\n",
		"drivers/d/Makefile": makefile,
	}
	for _, f := range files {
		m["drivers/d/"+f] = ""
	}
	return m
}

func TestComposites(t *testing.T) {
	r := crawl(t, dirTree(`
# shared members get the OR of their parents
snd-gus-lib-objs := gus_main.o gus_io.o
snd-gusclassic-objs := gusclassic.o
snd-gusmax-objs := gusmax.o
obj-$(CONFIG_SND_GUSCLASSIC) += snd-gusclassic.o snd-gus-lib.o
obj-$(CONFIG_SND_GUSMAX) += snd-gusmax.o snd-gus-lib.o
# nested composite and a member named like its composite
fsl-edma-trace-$(CONFIG_TRACING) := fsl-edma-trace.o
fsl-edma-objs := fsl-edma-main.o fsl-edma-common.o ${fsl-edma-trace-y}
obj-$(CONFIG_FSL_EDMA) += fsl-edma.o
mcf-edma-objs := mcf-edma-main.o fsl-edma-common.o ${fsl-edma-trace-y}
obj-$(CONFIG_MCF_EDMA) += mcf-edma.o
# := sees the earlier value of the variable it assigns
crypto_algapi-$(CONFIG_PROC_FS) += proc.o
crypto_algapi-y := algapi.o $(crypto_algapi-y)
obj-$(CONFIG_CRYPTO) += crypto_algapi.o
outer-y := inner.o
inner-y := leaf.o
inner-$(CONFIG_LEAF2) += leaf2.o
obj-$(CONFIG_OUTER) += outer.o
`, "gus_main.c", "gus_io.c", "gusclassic.c", "gusmax.c", "fsl-edma-main.c", "fsl-edma-common.c",
		"fsl-edma-trace.c", "mcf-edma-main.c", "proc.c", "algapi.c", "leaf.c", "leaf2.c"))
	expect(t, r, map[string]string{
		"drivers/d/gus_main.c":        "CONFIG_SND_GUSCLASSIC || CONFIG_SND_GUSMAX",
		"drivers/d/gusmax.c":          "CONFIG_SND_GUSMAX",
		"drivers/d/fsl-edma-common.c": "CONFIG_FSL_EDMA || CONFIG_MCF_EDMA",
		"drivers/d/fsl-edma-trace.c":  "(CONFIG_FSL_EDMA || CONFIG_MCF_EDMA) && CONFIG_TRACING=y",
		"drivers/d/algapi.c":          "CONFIG_CRYPTO",
		"drivers/d/proc.c":            "(CONFIG_CRYPTO && CONFIG_PROC_FS=y) || (CONFIG_CRYPTO=m && CONFIG_PROC_FS=m)",
		"drivers/d/leaf.c":            "CONFIG_OUTER",
		"drivers/d/leaf2.c":           "(CONFIG_LEAF2=m && CONFIG_OUTER=m) || (CONFIG_LEAF2=y && CONFIG_OUTER)",
	})
}

func TestConditionals(t *testing.T) {
	r := crawl(t, dirTree(`
ifeq ($(CONFIG_A),y)
obj-y += a.o
endif
ifneq ($(CONFIG_B),)
obj-y += b.o
else
obj-y += not_b.o
endif
ifdef CONFIG_C
obj-y += c.o
else ifeq ($(CONFIG_D),m)
obj-y += d.o
else ifneq "$(CONFIG_E)" "y"
obj-y += e.o
endif
ifndef CONFIG_F
obj-y += f.o
endif
ifeq ($(avx_supported),yes)
obj-$(CONFIG_G) += avx.o
endif
ifeq ($(ARCH),x86)
obj-y += x86.o
endif
ifeq ($(BITS),32)
obj-y += only32.o
endif
obj-y += foo_$(BITS).o
ifneq ($(CONFIG_HASH_LIST),"")
obj-y += hashes.o
else
obj-y += nohashes.o
endif
ifdef CONFIG_W
WIDTH := 64
else
WIDTH := 32
endif
ifeq ($(WIDTH),16)
obj-y += w16.o
endif
`, "a.c", "b.c", "not_b.c", "c.c", "d.c", "e.c", "f.c", "avx.c", "x86.c", "only32.c", "foo_32.c", "foo_64.c",
		"hashes.c", "nohashes.c", "w16.c"))
	expect(t, r, map[string]string{
		"drivers/d/a.c":      "CONFIG_A=y",
		"drivers/d/b.c":      "CONFIG_B",
		"drivers/d/not_b.c":  "!CONFIG_B",
		"drivers/d/c.c":      "CONFIG_C",
		"drivers/d/d.c":      "!CONFIG_C && CONFIG_D=m",
		"drivers/d/e.c":      "!CONFIG_C && !CONFIG_D=m && !CONFIG_E=y",
		"drivers/d/f.c":      "!CONFIG_F",
		"drivers/d/avx.c":    `"$(avx_supported) == yes" && CONFIG_G`,
		"drivers/d/x86.c":    "true",
		"drivers/d/only32.c": "",
		"drivers/d/foo_64.c": "true",
		"drivers/d/foo_32.c": "",
		// A string option may equal any text: its test is unknown.
		"drivers/d/hashes.c":   `!"$(CONFIG_HASH_LIST) == \"\""`,
		"drivers/d/nohashes.c": `"$(CONFIG_HASH_LIST) == \"\""`,
		"drivers/d/w16.c":      "",
	})
	// The 32-bit twin of a built 64-bit file is never built on x86_64.
	if _, st := r.Lookup("drivers/d/foo_32.c"); st != NotBuilt {
		t.Errorf("foo_32.c: %v, want NotBuilt", st)
	}
	if _, st := r.Lookup("drivers/d/only32.c"); st != Unlisted {
		t.Errorf("only32.c: %v, want Unlisted", st)
	}
}

// ifdef tests whether a variable has a value without expanding it, as
// make does: FOO = $(EMPTY) is defined, BAR := $(EMPTY) is not.
func TestIfdefUnexpanded(t *testing.T) {
	expect(t, crawl(t, dirTree(`
FOO = $(EMPTY)
BAR := $(EMPTY)
ifdef FOO
obj-y += foo.o
endif
ifdef BAR
obj-y += bar.o
endif
ifdef CONFIG_C
obj-$(CONFIG_D) += c.o
endif
`, "foo.c", "bar.c", "c.c")), map[string]string{
		"drivers/d/foo.c": "true",
		"drivers/d/bar.c": "",
		"drivers/d/c.c":   "CONFIG_C && CONFIG_D",
	})
}

// An else branch whose condition expands $(foreach), which pushes frames
// while it runs, keeps its condition.
func TestElseConditionForeach(t *testing.T) {
	r := crawl(t, dirTree(`
L := a b
ifdef CONFIG_X
obj-y += x.o
else ifeq ($(foreach v,$(L),$(v)),a b)
obj-y += y.o
endif
`, "x.c", "y.c"))
	expect(t, r, map[string]string{"drivers/d/x.c": "CONFIG_X", "drivers/d/y.c": "!CONFIG_X"})
}

func TestConditionalVariables(t *testing.T) {
	r := crawl(t, dirTree(`
AMDKFD_FILES := kfd_module.o
ifdef CONFIG_HSA_AMD_SVM
AMDKFD_FILES += kfd_svm.o
endif
amdgpu-y += $(AMDKFD_FILES)
obj-$(CONFIG_DRM_AMDGPU) += amdgpu.o
ifeq ($(CONFIG_I915_GVT),y)
include $(src)/gvt/Makefile
endif
obj-$(CONFIG_I915) += i915.o
`, "kfd_module.c", "kfd_svm.c", "gvt/gvt.c", "gvt/Makefile"))
	// The included Makefile appends to i915-y under the enclosing ifeq.
	r2 := crawl(t, func() map[string]string {
		m := dirTree(`
ifeq ($(CONFIG_I915_GVT),y)
include $(src)/gvt/Makefile
endif
i915-y += core.o
obj-$(CONFIG_I915) += i915.o
`, "core.c", "gvt/gvt.c")
		m["drivers/d/gvt/Makefile"] = "GVT_SOURCE := gvt.o\ni915-y += $(addprefix gvt/,$(GVT_SOURCE))\n"
		return m
	}())
	expect(t, r, map[string]string{
		"drivers/d/kfd_module.c": "CONFIG_DRM_AMDGPU",
		"drivers/d/kfd_svm.c":    "CONFIG_DRM_AMDGPU && CONFIG_HSA_AMD_SVM",
	})
	expect(t, r2, map[string]string{
		"drivers/d/core.c":    "CONFIG_I915",
		"drivers/d/gvt/gvt.c": "CONFIG_I915 && CONFIG_I915_GVT=y",
	})
	// ?= sets a variable where no earlier assignment did.
	expect(t, crawl(t, dirTree(`
ifdef CONFIG_A
FOO := a.o
endif
FOO ?= b.o
obj-y += $(FOO)
`, "a.c", "b.c")), map[string]string{
		"drivers/d/a.c": "CONFIG_A",
		"drivers/d/b.c": "!CONFIG_A",
	})
}

// include $(LIST) runs each file under the condition of its word, as
// amd/display/dc includes the Makefiles of the DC_LIBS it lists under
// ifdef CONFIG_DRM_AMD_DC_FP.
func TestConditionalInclude(t *testing.T) {
	m := dirTree(`
LIBS = a
ifdef CONFIG_FP
LIBS += b
endif
include $(addsuffix /Makefile,$(addprefix $(src)/,$(LIBS)))
amd-y += $(FILES)
obj-$(CONFIG_AMD) += amd.o
`, "a/x.c", "b/y.c")
	m["drivers/d/a/Makefile"] = "FILES += a/x.o\n"
	m["drivers/d/b/Makefile"] = "FILES += b/y.o\n"
	expect(t, crawl(t, m), map[string]string{
		"drivers/d/a/x.c": "CONFIG_AMD",
		"drivers/d/b/y.c": "CONFIG_AMD && CONFIG_FP",
	})
}

// Until v6.1 arch/x86/kernel built its head code and linker script through
// extra-y; later releases name the script in always-y.
func TestExtraObjects(t *testing.T) {
	m := dirTree(`
extra-y := head_$(BITS).o head$(BITS).o
extra-y += vmlinux.lds
always-$(CONFIG_X) += a.o
`, "head64.c", "vmlinux.lds.S", "a.c", "xen-head.S")
	m["drivers/d/head_64.S"] = "#include \"xen-head.S\"\n"
	expect(t, crawl(t, m), map[string]string{
		"drivers/d/head_64.S":     "true",
		"drivers/d/head64.c":      "true",
		"drivers/d/vmlinux.lds.S": "true",
		"drivers/d/a.c":           "CONFIG_X",
		"drivers/d/xen-head.S":    "true",
	})
}

// arch/riscv/Makefile builds -march strings by gluing text to a variable
// under one option after another; the alternatives double with each line
// and must not exhaust memory.
func TestGluedAlternatives(t *testing.T) {
	var mk strings.Builder
	mk.WriteString("march-$(CONFIG_RV32) := rv32ima\nmarch-$(CONFIG_RV64) := rv64ima\n")
	for i := range 24 {
		fmt.Fprintf(&mk, "march-$(CONFIG_EXT%d) := $(march-y)_x%d\n", i, i)
	}
	mk.WriteString("KBUILD_CFLAGS += -march=$(march-y)\nobj-y += a.o\nobj-$(CONFIG_B) += b-$(BITS).o\n")
	r := crawl(t, dirTree(mk.String(), "a.c", "b-64.c"))
	expect(t, r, map[string]string{"drivers/d/a.c": "true", "drivers/d/b-64.c": "CONFIG_B"})
}

func TestFunctions(t *testing.T) {
	r := crawl(t, dirTree(`
obj-$(subst m,y,$(CONFIG_A)) += a.o
obj-$(CONFIG_B:m=y) += b.o
SRCS := c.c d.c skip.c
obj-y += $(patsubst %.c,%.o,$(filter-out skip.c,$(SRCS)))
obj-y += $(addsuffix .o,e) $(addprefix sub/,f.o)
obj-y += $(foreach n,g h,$(n).o)
obj-y += $(if $(CONFIG_I),i.o,noti.o)
obj-y += $(notdir $(wildcard $(src)/w*.c:.c=.o))
lib-y := stub.o
lib-y := $(patsubst %.o,%.stub.o,$(lib-y))
obj-$(CONFIG_UNKNOWN) += $(shell echo x.o)
obj-$(findstring y, $(CONFIG_J) $(CONFIG_K)) += j.o
obj-$(shell true) += z.o
objname = $(n).o
obj-y += $(foreach n,k l,$(objname))
obj-y += $(or $(if $(CONFIG_O),o.o),noto.o) $(or ,p.o)
`, "a.c", "b.c", "c.c", "d.c", "skip.c", "e.c", "sub/f.c", "g.c", "h.c", "i.c", "noti.c", "stub.c", "j.c", "z.c", "k.c", "l.c", "o.c", "noto.c", "p.c"))
	if !slices.ContainsFunc(r.Errors, func(s string) bool { return strings.Contains(s, "opaque variable name obj-$(shell true) not assigned") }) {
		t.Errorf("Errors = %q; want the opaque obj-$(shell true)", r.Errors)
	}
	expect(t, r, map[string]string{
		"drivers/d/a.c":     "CONFIG_A",
		"drivers/d/b.c":     "CONFIG_B",
		"drivers/d/c.c":     "true",
		"drivers/d/d.c":     "true",
		"drivers/d/skip.c":  "",
		"drivers/d/e.c":     "true",
		"drivers/d/sub/f.c": "true",
		"drivers/d/g.c":     "true",
		"drivers/d/h.c":     "true",
		"drivers/d/i.c":     "CONFIG_I",
		"drivers/d/noti.c":  "!CONFIG_I",
		"drivers/d/stub.c":  "true",
		"drivers/d/j.c":     "CONFIG_J=y || CONFIG_K=y",
		"drivers/d/z.c":     "",
		"drivers/d/k.c":     "true",
		"drivers/d/l.c":     "true",
		"drivers/d/o.c":     "CONFIG_O",
		"drivers/d/noto.c":  "!CONFIG_O",
		"drivers/d/p.c":     "true",
	})
}

// addprefix and addsuffix apply to each word of their list, and to nothing
// when the list is empty: a conditional list must not list the bare prefix
// as a directory.
func TestAffixEmptyList(t *testing.T) {
	m := dirTree(`
objs-$(CONFIG_A) += a.o
obj-y += $(addprefix sub/,$(objs-y)) $(addprefix sub/,)
`, "sub/a.c", "sub/b.c")
	m["drivers/d/sub/Makefile"] = "obj-y += b.o\n"
	expect(t, crawl(t, m), map[string]string{"drivers/d/sub/a.c": "CONFIG_A=y", "drivers/d/sub/b.c": ""})
}

// A $ that ends a line is literal text.
func TestTrailingDollar(t *testing.T) {
	done := make(chan *Result, 1)
	go func() {
		r, _ := Crawl(tree(dirTree("X := a$\nobj-$(CONFIG_A) += a.o\n", "a.c")), Options{Arch: "x86"})
		done <- r
	}()
	select {
	case r := <-done:
		expect(t, r, map[string]string{"drivers/d/a.c": "CONFIG_A"})
	case <-time.After(10 * time.Second):
		t.Fatal("Crawl hangs on a trailing $")
	}
}

// net/l2tp builds an option's objects into the module of another:
// subst replaces the y of one variable with the value of the other. The
// crawler does not know L2TP_V3 is a bool, so its m stays possible.
func TestSubstConditional(t *testing.T) {
	r := crawl(t, dirTree(`
obj-$(CONFIG_L2TP) += l2tp_core.o
obj-$(subst y,$(CONFIG_L2TP),$(CONFIG_L2TP_V3)) += l2tp_netlink.o
obj-$(subst m,y,$(CONFIG_A)) += a.o
`, "l2tp_core.c", "l2tp_netlink.c", "a.c"))
	expect(t, r, map[string]string{
		"drivers/d/l2tp_core.c":    "CONFIG_L2TP",
		"drivers/d/l2tp_netlink.c": "(CONFIG_L2TP=m && CONFIG_L2TP_V3=y) || (CONFIG_L2TP=y && CONFIG_L2TP_V3=y) || CONFIG_L2TP_V3=m",
		"drivers/d/a.c":            "CONFIG_A",
	})
}

func TestMakefileSyntax(t *testing.T) {
	r := crawl(t, dirTree(`
# continuation lines and comments
obj-$(CONFIG_A) += a.o \
		   b.o # a comment with obj-y += c.o
define BODY
obj-y += defined.o
endef
override define OVER
obj-y += over_define.o
endef
$(obj)/gen.h: $(src)/gen.txt
	@echo obj-y += recipe.o
	$(call cmd,gen)
obj-y += after.o
override obj-y += over.o
export FOO := x
`, "a.c", "b.c", "c.c", "defined.c", "over_define.c", "recipe.c", "after.c", "over.c"))
	expect(t, r, map[string]string{
		"drivers/d/a.c":           "CONFIG_A",
		"drivers/d/b.c":           "CONFIG_A",
		"drivers/d/c.c":           "",
		"drivers/d/defined.c":     "",
		"drivers/d/over_define.c": "",
		"drivers/d/recipe.c":      "",
		"drivers/d/after.c":       "true",
		"drivers/d/over.c":        "true",
	})
}

// Constructs the evaluator does not model leave notes in Errors: $(eval)
// of a macro it lacks or where it expands more than make does, and words
// of object lists made by unmodelled functions.
func TestNotes(t *testing.T) {
	r := crawl(t, dirTree(`
define BODY
obj-y += $(1).o
endef
$(foreach t,gen,$(eval $(call BODY,$(t))))
$(eval $(call UNDEFINED,lost))
$(if $(CONFIG_A),$(eval obj-y += cond.o))
obj-$(CONFIG_A) += $(shell echo x.o)
foo-y := $(call mk,y.o) z.o
obj-y += foo.o
`, "gen.c", "lost.c", "cond.c", "x.c", "y.c", "z.c", "foo.c"))
	for _, w := range []string{
		"drivers/d/Makefile:5: $(eval $(call UNDEFINED,lost)) not evaluated",
		"drivers/d/Makefile:6: $(eval obj-y += cond.o) not evaluated",
		"drivers/d/Makefile: opaque word $(shell echo x.o) in obj-y",
		"drivers/d/Makefile: opaque word $(call mk,y.o) in foo-y",
	} {
		if !slices.Contains(r.Errors, w) {
			t.Errorf("missing note %q in %q", w, r.Errors)
		}
	}
	expect(t, r, map[string]string{"drivers/d/gen.c": "true", "drivers/d/lost.c": "", "drivers/d/cond.c": "",
		"drivers/d/x.c": "", "drivers/d/z.c": "true"})
}

func TestDirectories(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":         "drivers-y := drivers/\n",
		"drivers/Makefile": "obj-$(CONFIG_INPUT) += input/\nobj-$(CONFIG_SERIO) += input/serio/\nobj-$(CONFIG_X) += shared/\nobj-$(CONFIG_SUB) += sub/\n",
		// A directory listed by its grandparent does not inherit its
		// parent's condition.
		"drivers/input/Makefile":       "obj-$(CONFIG_INPUT) += input-core.o\n",
		"drivers/input/input-core.c":   "",
		"drivers/input/serio/Makefile": "obj-y += serio.o\n",
		"drivers/input/serio/serio.c":  "",
		// A directory listed twice gets the OR; ../ is normalized.
		"drivers/sub/Makefile":    "obj-$(CONFIG_Y) += ../shared/\nsubdir-$(CONFIG_Z) += z\n",
		"drivers/shared/Makefile": "obj-y += s.o\n",
		"drivers/shared/s.c":      "",
		"drivers/sub/z/Makefile":  "obj-y += z.o\n",
		"drivers/sub/z/z.c":       "",
		// Kbuild wins over Makefile.
		"drivers/sub/z/Kbuild":           "obj-$(CONFIG_ZZ) += z.o\n",
		"drivers/input/serio/unlisted.c": "",
		"drivers/input/serio/serio.h":    "",
		// A directory with a Makefile no parent lists is never entered.
		"drivers/never/Makefile": "obj-y += never.o\n",
		"drivers/never/never.c":  "",
	})
	expect(t, r, map[string]string{
		"drivers/input/input-core.c":  "CONFIG_INPUT",
		"drivers/input/serio/serio.c": "CONFIG_SERIO=y",
		"drivers/shared/s.c":          "(CONFIG_SUB=y && CONFIG_Y=y) || CONFIG_X=y",
		// subdir-y descends without linking: a bool object there is never
		// built, a tristate one only as a module.
		"drivers/sub/z/z.c": "CONFIG_SUB && CONFIG_Z && CONFIG_ZZ=m",
	})
	if _, st := r.Lookup("drivers/input/serio/unlisted.c"); st != Unlisted {
		t.Errorf("unlisted.c: %v, want Unlisted", st)
	}
	// A header no file includes is unlisted; a Makefile is no source.
	if _, st := r.Lookup("drivers/input/serio/serio.h"); st != Unlisted {
		t.Errorf("serio.h: %v, want Unlisted", st)
	}
	if _, st := r.Lookup("drivers/input/serio/Makefile"); st != NotSource {
		t.Errorf("Makefile: %v, want NotSource", st)
	}
	if _, st := r.Lookup("drivers/never/never.c"); st != NotBuilt {
		t.Errorf("never.c: %v, want NotBuilt", st)
	}
	// The walk up the directories of an absolute path ends at the root.
	if _, st := r.Lookup("/drivers/never/never.c"); st != NotBuilt {
		t.Errorf("/drivers/never/never.c: %v, want NotBuilt", st)
	}
}

func TestOldArchDirectory(t *testing.T) {
	// Before v2.6.24 x86-64 lived in arch/x86_64.
	r := crawl(t, map[string]string{
		"Makefile":                    "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/x86_64/Makefile":        "core-y += arch/x86_64/kernel/\n",
		"arch/x86_64/kernel/Makefile": "obj-y += setup.o\n",
		"arch/x86_64/kernel/setup.c":  "",
		"arch/i386/kernel/setup.c":    "",
	})
	expect(t, r, map[string]string{"arch/x86_64/kernel/setup.c": "true"})
	if _, st := r.Lookup("arch/i386/kernel/setup.c"); st != NotBuilt {
		t.Errorf("arch/i386 file: %v, want NotBuilt", st)
	}
}

func TestBits(t *testing.T) {
	files := map[string]string{
		"Makefile":                   "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/x86/Makefile":          "core-y += arch/x86/kernel/\n",
		"arch/x86/kernel/Makefile":   "obj-y += entry_$(BITS).o\nobj-$(CONFIG_X86_32) += vm86_32.o\n",
		"arch/x86/kernel/entry_32.S": "", "arch/x86/kernel/entry_64.S": "", "arch/x86/kernel/vm86_32.c": "",
	}
	// x86 crawls as x86-64 by default, and as i386 with Bits 32.
	r := crawl(t, files)
	expect(t, r, map[string]string{"arch/x86/kernel/entry_64.S": "true", "arch/x86/kernel/vm86_32.c": "CONFIG_X86_32"})
	if _, st := r.Lookup("arch/x86/kernel/entry_32.S"); st != NotBuilt {
		t.Errorf("entry_32.S on x86-64: %v, want NotBuilt", st)
	}
	r32, err := Crawl(tree(files), Options{Arch: "x86", Bits: "32"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, r32, map[string]string{"arch/x86/kernel/entry_32.S": "true", "arch/x86/kernel/vm86_32.c": "CONFIG_X86_32"})
	if _, st := r32.Lookup("arch/x86/kernel/entry_64.S"); st != NotBuilt {
		t.Errorf("entry_64.S on i386: %v, want NotBuilt", st)
	}
}

func TestArchOwnRules(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                     "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/x86/Makefile":            "core-y += arch/x86/kernel/\n",
		"arch/x86/kernel/Makefile":     "obj-y += setup.o\n",
		"arch/x86/entry/vdso/Makefile": "vobjs-y += vclock.o\n",
		"arch/x86/um/Makefile":         "obj-y += ldt.o\n",
		"arch/x86/kernel/setup.c":      "", "arch/x86/entry/vdso/vclock.c": "", "arch/x86/um/ldt.c": "",
	})
	for p, want := range map[string]Status{
		"arch/x86/kernel/setup.c": Built,
		// The arch's own rules build it; no Makefile the crawl follows
		// lists it.
		"arch/x86/entry/vdso/vclock.c": Unlisted,
		// User-mode Linux on an x86 host is another arch.
		"arch/x86/um/ldt.c": NotBuilt,
	} {
		if _, st := r.Lookup(p); st != want {
			t.Errorf("%s: %v, want %v", p, st, want)
		}
	}
}

// arch/x86 links its boot image, real-mode blob and purgatory from lists of
// its own, and its Makefiles enter the boot and real-mode directories in
// every configuration though no list names them.
func TestOwnLists(t *testing.T) {
	files := map[string]string{
		"Makefile":                            "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/x86/Makefile":                   "core-y += arch/x86/\n",
		"arch/x86/Kbuild":                     "obj-y += realmode/\nobj-$(CONFIG_KEXEC_FILE) += purgatory/\n",
		"arch/x86/boot/Makefile":              "subdir- := compressed\nsetup-y += main.o\nsetup-$(CONFIG_APM) += apm.o\n",
		"arch/x86/boot/compressed/Makefile":   "vmlinux-objs-y := $(obj)/vmlinux.lds $(obj)/misc.o\nvmlinux-objs-$(CONFIG_SEV) += $(obj)/sev.o $(obj)/cpuflags.o\n",
		"arch/x86/boot/compressed/cpuflags.c": "#include \"../cpuflags.c\"\n",
		"arch/x86/realmode/Makefile":          "subdir- := rm\nobj-y += init.o\n",
		"arch/x86/realmode/rm/Makefile":       "realmode-y += header.o\n",
		"arch/x86/purgatory/Makefile":         "purgatory-y := purgatory.o\nobj-$(CONFIG_KEXEC_FILE) += kexec-purgatory.o\n",
		"arch/arm64/Makefile":                 "core-y += arch/arm64/kernel/\n",
	}
	for _, src := range []string{"arch/x86/boot/main.c", "arch/x86/boot/apm.c", "arch/x86/boot/cpuflags.c",
		"arch/x86/boot/compressed/vmlinux.lds.S", "arch/x86/boot/compressed/misc.c", "arch/x86/boot/compressed/sev.c",
		"arch/x86/realmode/init.c", "arch/x86/realmode/rm/header.S", "arch/x86/purgatory/purgatory.c"} {
		files[src] = ""
	}
	expect(t, crawl(t, files), map[string]string{
		"arch/x86/boot/main.c":                   "true",
		"arch/x86/boot/apm.c":                    "CONFIG_APM=y",
		"arch/x86/boot/compressed/vmlinux.lds.S": "true",
		"arch/x86/boot/compressed/misc.c":        "true",
		"arch/x86/boot/compressed/sev.c":         "CONFIG_SEV=y",
		"arch/x86/boot/cpuflags.c":               "CONFIG_SEV=y",
		"arch/x86/realmode/rm/header.S":          "true",
		"arch/x86/purgatory/purgatory.c":         "CONFIG_KEXEC_FILE",
	})
	// Other arches never enter arch/x86's directories.
	r, err := Crawl(tree(files), Options{Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if _, st := r.Lookup("arch/x86/boot/main.c"); st != NotBuilt {
		t.Errorf("arch/x86/boot/main.c on arm64: %v, want NotBuilt", st)
	}
}

// arm64's nVHE hypervisor lists its sources, some from the directories
// above, in hyp-obj-y and links them into kvm_nvhe.o under the directory's
// condition.
func TestNVHEList(t *testing.T) {
	files := map[string]string{
		"Makefile":                             "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/arm64/Makefile":                  "core-y += arch/arm64/kvm/\n",
		"arch/arm64/kvm/Makefile":              "obj-$(CONFIG_KVM) += hyp/\n",
		"arch/arm64/kvm/hyp/Makefile":          "obj-$(CONFIG_KVM) += vhe/ nvhe/ pgtable.o\n",
		"arch/arm64/kvm/hyp/vhe/Makefile":      "obj-y := switch.o ../vgic.o\n",
		"arch/arm64/kvm/hyp/nvhe/Makefile":     "lib-objs := clear_page.o\nlib-objs := $(addprefix ../../../lib/, $(lib-objs))\nhyp-obj-y := hyp-init.o ../vgic.o\nhyp-obj-$(CONFIG_LIST_HARDENED) += list_debug.o\nhyp-obj-y += $(lib-objs)\nhyp-obj := $(patsubst %.o,%.nvhe.o,$(hyp-obj-y))\nobj-y := kvm_nvhe.o\ntargets += $(hyp-obj)\n",
		"arch/arm64/kvm/hyp/nvhe/hyp-init.S":   "",
		"arch/arm64/kvm/hyp/nvhe/list_debug.c": "",
		"arch/arm64/kvm/hyp/vhe/switch.c":      "",
		"arch/arm64/kvm/hyp/vgic.c":            "",
		"arch/arm64/kvm/hyp/pgtable.c":         "",
		"arch/arm64/lib/clear_page.S":          "",
	}
	r, err := Crawl(tree(files), Options{Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, r, map[string]string{
		"arch/arm64/kvm/hyp/nvhe/hyp-init.S":   "CONFIG_KVM",
		"arch/arm64/kvm/hyp/nvhe/list_debug.c": "CONFIG_KVM && CONFIG_LIST_HARDENED=y",
		"arch/arm64/kvm/hyp/vhe/switch.c":      "CONFIG_KVM=y",
		"arch/arm64/kvm/hyp/vgic.c":            "CONFIG_KVM",
		"arch/arm64/lib/clear_page.S":          "CONFIG_KVM",
	})
}

// The x86 vDSO links its objects into images, which obj-y lists: vobjs-y
// is built when the 64-bit or x32 image is, vobjs32-y with the 32-bit one,
// and before v3.16 the images were vdso.o and vdsox32.o. Without its images
// a list stays unlisted. Since v7.0 each vDSO has a directory, entered
// under its condition, whose sources include common ones.
func TestVDSOLists(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/x86/Makefile":       "core-y += arch/x86/entry/ arch/x86/vdso/ arch/x86/lone/\n",
		"arch/x86/entry/Makefile": "obj-y += vdso/\n",
		"arch/x86/entry/vdso/Makefile": `
VDSO64-$(CONFIG_X86_64)		:= y
VDSOX32-$(CONFIG_X86_X32_ABI)	:= y
VDSO32-$(CONFIG_X86_32)		:= y
VDSO32-$(CONFIG_IA32_EMULATION)	:= y
vobjs-y := vdso-note.o vclock_gettime.o
vobjs32-y := vdso32/note.o
vobjs-$(CONFIG_X86_SGX)	+= vsgx.o
obj-y += vma.o
vdso_img-$(VDSO64-y)		+= 64
vdso_img-$(VDSOX32-y)		+= x32
vdso_img-$(VDSO32-y)		+= 32
vdso_img_objs := $(vdso_img-y:%=vdso-image-%.o)
obj-y += $(vdso_img_objs)
obj-$(CONFIG_X86_64) += vdso64/
`,
		"arch/x86/entry/vdso/vdso-note.S": "", "arch/x86/entry/vdso/vclock_gettime.c": "",
		"arch/x86/entry/vdso/vsgx.S": "", "arch/x86/entry/vdso/vdso32/note.S": "", "arch/x86/entry/vdso/vma.c": "",
		"arch/x86/entry/vdso/vdso64/Makefile":  "vobjs-y := vgetcpu.o\n",
		"arch/x86/entry/vdso/vdso64/vgetcpu.c": "#include \"common/vgetcpu.c\"\n",
		"arch/x86/entry/vdso/common/vgetcpu.c": "",
		"arch/x86/vdso/Makefile": `
VDSO64-$(CONFIG_X86_64)		:= y
vobjs-y := old.o
obj-$(VDSO64-y)			+= vma.o vdso.o
`,
		"arch/x86/vdso/old.c": "", "arch/x86/vdso/vma.c": "", "arch/x86/vdso/vdso.S": "",
		"arch/x86/lone/Makefile": "obj-y += lone.o\n",
		"arch/x86/lone/lone.c":   "",
	})
	expect(t, r, map[string]string{
		"arch/x86/entry/vdso/vclock_gettime.c": "CONFIG_X86_64=y || CONFIG_X86_X32_ABI=y",
		"arch/x86/entry/vdso/vsgx.S":           "(CONFIG_X86_64=y || CONFIG_X86_X32_ABI=y) && CONFIG_X86_SGX=y",
		"arch/x86/entry/vdso/vdso32/note.S":    "CONFIG_IA32_EMULATION=y || (!CONFIG_IA32_EMULATION=y && CONFIG_X86_32=y)",
		"arch/x86/entry/vdso/vdso64/vgetcpu.c": "CONFIG_X86_64",
		"arch/x86/entry/vdso/common/vgetcpu.c": "CONFIG_X86_64",
		"arch/x86/vdso/old.c":                  "CONFIG_X86_64=y",
	})
	// A vDSO Makefile without its images.
	r = crawl(t, map[string]string{
		"Makefile":                     "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/x86/Makefile":            "core-y += arch/x86/entry/vdso/\n",
		"arch/x86/entry/vdso/Makefile": "vobjs-y := vclock.o\nobj-y += vma.o\n",
		"arch/x86/entry/vdso/vclock.c": "", "arch/x86/entry/vdso/vma.c": "",
	})
	if _, st := r.Lookup("arch/x86/entry/vdso/vclock.c"); st != Unlisted {
		t.Errorf("vclock.c without an image: %v, want unlisted", st)
	}
}

func TestKernelOnly(t *testing.T) {
	for p, want := range map[string]bool{
		"kernel/signal.c":                             true,
		"arch/x86/kernel/head_64.S":                   true,
		"arch/x86/purgatory/purgatory.c":              true,
		"include/linux/kernel.h":                      false,
		"arch/x86/include/asm/pvclock.h":              false,
		"arch/x86/boot/main.c":                        false,
		"arch/x86/boot/compressed/misc.c":             false,
		"arch/powerpc/boot/main.c":                    false,
		"arch/x86/realmode/rm/wakemain.c":             false,
		"arch/x86/kernel/acpi/realmode/wakemain.c":    false,
		"arch/x86/entry/vdso/vdso32/vclock_gettime.c": false,
		"arch/x86/vdso/vclock_gettime.c":              false,
		"arch/arm64/kernel/vdso32/vgettimeofday.c":    false,
		"lib/vdso/gettimeofday.c":                     false,
		// The real-mode trampoline includes it.
		"arch/x86/kernel/verify_cpu.S": false,
	} {
		if got := kernelOnly(p); got != want {
			t.Errorf("kernelOnly(%s) = %v, want %v", p, got, want)
		}
	}
}

// Assembly files define __ASSEMBLY__, C files do not, and headers are
// compiled both ways.
func TestCodeOf(t *testing.T) {
	for p, want := range map[string]kcond.Code{
		"kernel/fork.c":             {Kernel: true},
		"arch/x86/kernel/head_64.S": {Kernel: true, Assembly: kcond.True},
		"arch/x86/boot/header.S":    {Assembly: kcond.True},
		"include/linux/linkage.h":   {Assembly: kcond.Unknown},
	} {
		if got := CodeOf(p); got != want {
			t.Errorf("CodeOf(%s) = %+v, want %+v", p, got, want)
		}
	}
}

// $(eval) runs the Makefile lines it is given under the current
// condition: drivers/platform/x86/intel and lenovo turn their target lists
// into obj- lines with $(foreach ..., $(eval $(call ...))), each under the
// condition of its word, and generic_pt evaluates a $(foreach) of calls.
func TestEval(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                      "drivers-y := drivers/\n",
		"drivers/Makefile":              "obj-y += platform/x86/ pt/\n",
		"drivers/platform/x86/Makefile": "obj-y += intel/ lenovo/\n",
		"drivers/platform/x86/intel/Makefile": `
intel-target-$(CONFIG_INTEL_HID_EVENT) += hid.o
intel-target-$(CONFIG_INTEL_VSEC) += vsec.o
define INTEL_OBJ_TARGET
intel-$(1)-y := $(1).o
obj-$(2) += intel-$(1).o
endef
$(foreach target, $(basename $(intel-target-y)), $(eval $(call INTEL_OBJ_TARGET,$(target),y)))
$(foreach target, $(basename $(intel-target-m)), $(eval $(call INTEL_OBJ_TARGET,$(target),m)))
`,
		"drivers/platform/x86/lenovo/Makefile": `
lenovo-target-$(CONFIG_LENOVO_YMC) += ymc.o
define LENOVO_OBJ_TARGET
lenovo-$(1)-y := $(1).o
obj-$(2) += lenovo-$(1).o
endef
$(foreach target, $(basename $(lenovo-target-y)), $(eval $(call LENOVO_OBJ_TARGET,$(target),y)))
$(foreach target, $(basename $(lenovo-target-m)), $(eval $(call LENOVO_OBJ_TARGET,$(target),m)))
`,
		"drivers/pt/Makefile": `
iommu_pt_fmt-$(CONFIG_IOMMU_PT_AMDV1) += amdv1
iommu_pt_fmt-$(CONFIG_IOMMU_PT_X86_64) += x86_64
define create_format
obj-$(2) += iommu_$(1).o
CFLAGS_kunit_iommu_$(1).o += -DGENERIC_PT_KUNIT=1

endef
$(eval $(foreach fmt,$(iommu_pt_fmt-y),$(call create_format,$(fmt),y)))
$(eval $(foreach fmt,$(iommu_pt_fmt-m),$(call create_format,$(fmt),m)))
`,
		"drivers/platform/x86/intel/hid.c": "", "drivers/platform/x86/intel/vsec.c": "",
		"drivers/platform/x86/lenovo/ymc.c": "",
		"drivers/pt/iommu_amdv1.c":          "", "drivers/pt/iommu_x86_64.c": "",
	})
	expect(t, r, map[string]string{
		"drivers/platform/x86/intel/hid.c":  "CONFIG_INTEL_HID_EVENT",
		"drivers/platform/x86/intel/vsec.c": "CONFIG_INTEL_VSEC",
		"drivers/platform/x86/lenovo/ymc.c": "CONFIG_LENOVO_YMC",
		"drivers/pt/iommu_amdv1.c":          "CONFIG_IOMMU_PT_AMDV1",
		"drivers/pt/iommu_x86_64.c":         "CONFIG_IOMMU_PT_X86_64",
	})
	if len(r.Errors) > 0 {
		t.Errorf("Errors = %q, want none", r.Errors)
	}
}

// A source is compiled into a module where obj-m lists its object and
// obj-y does not, as Kbuild filters obj-m by obj-y, and into the kernel
// otherwise; composite members and #included files follow their object,
// and the other lists are linked into the kernel. aha152x.c is compiled on
// its own and #included into aha152x_cs. intel's loops list an m target in
// obj-m only, since make keeps intel-target-m apart. A composite links its
// foo-m members only when it is a module itself.
func TestModules(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":         "drivers-y := drivers/\n",
		"drivers/Makefile": "obj-y += d/ scsi/ platform/\n",
		"drivers/d/Makefile": `
obj-$(CONFIG_P) += lp.o
obj-$(CONFIG_M) += mxc-clk.o
mxc-clk-objs += clk.o
obj-$(CONFIG_A) += both.o
obj-$(CONFIG_B) += both.o
lib-$(CONFIG_L) += lib.o
obj-y += always.o
obj-$(CONFIG_F) += fan.o
fan-objs := fan_core.o
fan-$(CONFIG_H) += fan_hwmon.o
`,
		"drivers/scsi/Makefile":       "obj-$(CONFIG_S) += aha152x.o\nobj-$(CONFIG_PC) += aha152x_cs.o\naha152x_cs-objs := aha152x_core.o\n",
		"drivers/scsi/aha152x_core.c": "#include \"aha152x.c\"\n",
		"drivers/scsi/aha152x.c":      "",
		"drivers/platform/Makefile": `
intel-target-$(CONFIG_HID) += hid.o
define INTEL_OBJ_TARGET
intel-$(1)-y := $(1).o
obj-$(2) += intel-$(1).o
endef
$(foreach target, $(basename $(intel-target-y)), $(eval $(call INTEL_OBJ_TARGET,$(target),y)))
$(foreach target, $(basename $(intel-target-m)), $(eval $(call INTEL_OBJ_TARGET,$(target),m)))
`,
		"drivers/platform/hid.c": "",
		"drivers/d/lp.c":         "", "drivers/d/clk.c": "", "drivers/d/both.c": "", "drivers/d/lib.c": "", "drivers/d/always.c": "",
		"drivers/d/fan_core.c": "", "drivers/d/fan_hwmon.c": "",
	})
	for p, want := range map[string][3]string{
		"drivers/d/lp.c":         {"CONFIG_P", "CONFIG_P=y", "CONFIG_P=m"},
		"drivers/d/clk.c":        {"CONFIG_M", "CONFIG_M=y", "CONFIG_M=m"},
		"drivers/d/both.c":       {"CONFIG_A || CONFIG_B", "CONFIG_A=y || CONFIG_B=y", "(CONFIG_A=m || CONFIG_B=m) && !CONFIG_A=y && !CONFIG_B=y"},
		"drivers/d/lib.c":        {"CONFIG_L", "CONFIG_L", "false"},
		"drivers/d/always.c":     {"true", "true", "false"},
		"drivers/scsi/aha152x.c": {"CONFIG_PC || CONFIG_S", "CONFIG_PC=y || CONFIG_S=y", "CONFIG_PC=m || CONFIG_S=m"},
		"drivers/platform/hid.c": {"CONFIG_HID", "CONFIG_HID=y", "CONFIG_HID=m"},
		// A built-in composite leaves its fan-m members out.
		"drivers/d/fan_hwmon.c": {"(CONFIG_F && CONFIG_H=y) || (CONFIG_F=m && CONFIG_H=m)", "CONFIG_F=y && CONFIG_H=y", "CONFIG_F=m && CONFIG_H"},
	} {
		files, _ := r.Lookup(p)
		builtin, module := r.Module(p)
		for i, got := range []*kcond.Expr{files, builtin, module} {
			w, err := kcond.Parse(want[i])
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				got = kcond.Const(false)
			}
			if eq, ok := kcond.Equal(got, w); !ok || !eq {
				t.Errorf("%s: condition %d is %s, want %s", p, i, got, w)
			}
		}
	}
}

// An obj-y object is compiled only where its directory has need-builtin,
// which the top directories have and a directory passes to those its obj-y
// lists. A directory entered through obj-m or subdir-y alone compiles its
// modules, lib-y and always-y objects, not its obj-y ones.
func TestBuiltinNeedsLinkedDirectory(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":         "drivers-y := drivers/\n",
		"drivers/Makefile": "obj-$(CONFIG_PIN) += pinctrl/\nobj-m += mod/\nobj-y += core/\n",
		"drivers/pinctrl/Makefile": `
obj-$(CONFIG_MESON8) += meson8.o
obj-y += plain.o
lib-y += lib.o
always-y += gen.o
obj-y += sub/
obj-$(CONFIG_T) += tools/
subdir-y += tools
`,
		"drivers/pinctrl/meson8.c": "", "drivers/pinctrl/plain.c": "", "drivers/pinctrl/lib.c": "", "drivers/pinctrl/gen.c": "",
		"drivers/pinctrl/sub/Makefile":   "obj-y += s.o\n",
		"drivers/pinctrl/sub/s.c":        "",
		"drivers/pinctrl/tools/Makefile": "obj-y += t.o\n",
		"drivers/pinctrl/tools/t.c":      "",
		"drivers/mod/Makefile":           "obj-$(CONFIG_B) += b.o\nobj-$(CONFIG_B) += deeper/\n",
		"drivers/mod/b.c":                "",
		"drivers/mod/deeper/Makefile":    "obj-y += d.o\n",
		"drivers/mod/deeper/d.c":         "",
		"drivers/core/Makefile":          "obj-$(CONFIG_C) += c.o\n",
		"drivers/core/c.c":               "",
	})
	for p, want := range map[string][3]string{
		"drivers/pinctrl/meson8.c": {"(CONFIG_PIN=y && CONFIG_MESON8=y) || (CONFIG_PIN && CONFIG_MESON8=m)", "CONFIG_PIN=y && CONFIG_MESON8=y", "CONFIG_PIN && CONFIG_MESON8=m"},
		"drivers/pinctrl/plain.c":  {"CONFIG_PIN=y", "CONFIG_PIN=y", "false"},
		"drivers/pinctrl/lib.c":    {"CONFIG_PIN", "CONFIG_PIN", "false"},
		"drivers/pinctrl/gen.c":    {"CONFIG_PIN", "CONFIG_PIN", "false"},
		// sub/ inherits need-builtin from pinctrl/.
		"drivers/pinctrl/sub/s.c": {"CONFIG_PIN=y", "CONFIG_PIN=y", "false"},
		// tools/ is linked where obj-y lists it, entered by subdir-y too.
		"drivers/pinctrl/tools/t.c": {"CONFIG_PIN=y && CONFIG_T=y", "CONFIG_PIN=y && CONFIG_T=y", "false"},
		"drivers/mod/b.c":           {"CONFIG_B=m", "false", "CONFIG_B=m"},
		// Nothing under a module-only directory is ever linked.
		"drivers/mod/deeper/d.c": {"false", "false", "false"},
		"drivers/core/c.c":       {"CONFIG_C", "CONFIG_C=y", "CONFIG_C=m"},
	} {
		files, _ := r.Lookup(p)
		builtin, module := r.Module(p)
		for i, got := range []*kcond.Expr{files, builtin, module} {
			w, err := kcond.Parse(want[i])
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				got = kcond.Const(false)
			}
			if eq, ok := kcond.Equal(got, w); !ok || !eq {
				t.Errorf("%s: condition %d is %s, want %s", p, i, got, w)
			}
		}
	}
}

// Define tells under which conditions a source is compiled with a macro a
// -D flag defines, and without it: from ccflags-y, but not ccflags-m,
// which Kbuild does not read, from CFLAGS_x.o, and from the flags of the
// sources that #include it, along every path. A := assignment keeps
// repeated -D words apart.
func TestDefines(t *testing.T) {
	files := dirTree(`
obj-$(CONFIG_D) += a.o b.o
ccflags-$(CONFIG_D_DEBUG) += -DDEBUG
ccflags-$(CONFIG_M) += -DM
CFLAGS_b.o = -DA -D B=1
CFLAGS_a.o := -D X -D Y
obj-$(CONFIG_T) += top.o
CFLAGS_top.o = -DT
`, "a.c", "inc.c")
	files["drivers/d/b.c"] = "#include \"inc.c\"\n"
	files["drivers/d/top.c"] = "#include \"p.c\"\n#include \"q.c\"\n"
	files["drivers/d/p.c"] = "#ifdef CONFIG_P\n#include \"shared.c\"\n#endif\n"
	files["drivers/d/q.c"] = "#ifdef CONFIG_Q\n#include \"shared.c\"\n#endif\n"
	files["drivers/d/shared.c"] = ""
	files["drivers/Makefile"] = "obj-y += d/ e/\n"
	files["drivers/e/Makefile"] = "obj-$(CONFIG_E) += e.o\n"
	files["drivers/e/e.c"] = ""
	r := crawl(t, files)
	for _, c := range []struct{ path, macro, set, unset string }{
		{"drivers/d/a.c", "DEBUG", "CONFIG_D && CONFIG_D_DEBUG=y", "CONFIG_D && !CONFIG_D_DEBUG=y"},
		{"drivers/d/a.c", "M", "CONFIG_D && CONFIG_M=y", "CONFIG_D && !CONFIG_M=y"},
		{"drivers/d/a.c", "A", "false", "CONFIG_D"},
		{"drivers/d/a.c", "X", "CONFIG_D", "false"},
		{"drivers/d/a.c", "Y", "CONFIG_D", "false"},
		{"drivers/d/shared.c", "T", "CONFIG_T && (CONFIG_P=y || CONFIG_Q=y)", "false"},
		{"drivers/d/b.c", "A", "CONFIG_D", "false"},
		{"drivers/d/b.c", "B", "CONFIG_D", "false"},
		{"drivers/d/inc.c", "A", "CONFIG_D", "false"},
		{"drivers/d/inc.c", "DEBUG", "CONFIG_D && CONFIG_D_DEBUG=y", "CONFIG_D && !CONFIG_D_DEBUG=y"},
		{"drivers/e/e.c", "DEBUG", "false", "CONFIG_E"},
	} {
		set, unset := r.Define(c.path, c.macro)
		for i, got := range []*kcond.Expr{set, unset} {
			want, err := kcond.Parse([]string{c.set, c.unset}[i])
			if err != nil {
				t.Fatal(err)
			}
			if eq, ok := kcond.Equal(got, want); !ok || !eq {
				t.Errorf("Define(%s, %s)[%d] = %s, want %s", c.path, c.macro, i, got, want)
			}
		}
	}
}

// A fragment finds its own directory from the last word of
// $(MAKEFILE_LIST), as lib/vdso/Makefile.include does; abspath keeps paths
// in the tree, and firstword and lastword pick words exactly.
func TestMakefileList(t *testing.T) {
	files := dirTree(`
include $(srctree)/lib/x/Makefile.include
obj-y += ../../$(HERE)part.o $(firstword b.o c.o) $(lastword d.o e.o)
`, "b.c", "c.c", "d.c", "e.c")
	files["lib/x/Makefile.include"] = "HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))\n"
	files["lib/x/part.c"] = ""
	expect(t, crawl(t, files), map[string]string{"lib/x/part.c": "true", "drivers/d/b.c": "true", "drivers/d/c.c": "",
		"drivers/d/d.c": "", "drivers/d/e.c": "true"})
}

// $(call) substitutes its arguments into the macro's value, which is then
// expanded as any text, so two calls in one list each keep theirs. A macro
// that calls itself under $(if), whose branches are both expanded, stops
// at maxCalls.
func TestCall(t *testing.T) {
	r := crawl(t, dirTree(`
mk = $(1).o
pair = $(call mk,$(1)) $(call mk,$2)
objs = $(call pair,a,b) $(call mk,c)
obj-y += $(objs)
obj-$(CONFIG_D) += $(call mk,d)
loop = $(if $(1),$(call loop,$(1))) $(1)
obj-y += $(call loop,e.o)
`, "a.c", "b.c", "c.c", "d.c", "e.c"))
	expect(t, r, map[string]string{"drivers/d/a.c": "true", "drivers/d/b.c": "true", "drivers/d/c.c": "true", "drivers/d/d.c": "CONFIG_D",
		"drivers/d/e.c": "true"})
}

// Host and user programs are compiled when their directory is built:
// arch/x86/Makefile builds relocs, which processes the image, in every x86
// build, and samples build user programs under their options.
func TestPrograms(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                     "include $(srctree)/arch/$(SRCARCH)/Makefile\ndrivers-y += drivers/\ndrivers-$(CONFIG_SAMPLES) += samples/\n",
		"arch/x86/Makefile":            "core-y += arch/x86/\n",
		"arch/x86/tools/Makefile":      "hostprogs += relocs\nrelocs-objs := relocs_32.o relocs_64.o\n",
		"arch/x86/tools/relocs_32.c":   "#include \"relocs.c\"\n",
		"arch/x86/tools/relocs_64.c":   "#include \"relocs.c\"\n",
		"arch/x86/tools/relocs.c":      "",
		"drivers/Makefile":             "obj-$(CONFIG_OSS) += oss/\n",
		"drivers/oss/Makefile":         "hostprogs-y := bin2hex\n",
		"drivers/oss/bin2hex.c":        "",
		"samples/Makefile":             "subdir-$(CONFIG_SAMPLE_LANDLOCK) += landlock\n",
		"samples/landlock/Makefile":    "userprogs-always-y := sandboxer\n",
		"samples/landlock/sandboxer.c": "",
	})
	expect(t, r, map[string]string{
		"arch/x86/tools/relocs.c":      "true",
		"drivers/oss/bin2hex.c":        "CONFIG_OSS",
		"samples/landlock/sandboxer.c": "CONFIG_SAMPLES && CONFIG_SAMPLE_LANDLOCK",
	})
}

// .s targets are compiled from C for the offsets headers they generate: the
// top-level Kbuild's kernel/bounds.s and asm-offsets.s, arch/x86/kvm's
// kvm-asm-offsets.s.
func TestAssemblyTargets(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":          "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"Kbuild":            "targets := kernel/bounds.s\ntargets += arch/$(SRCARCH)/kernel/asm-offsets.s\n",
		"arch/x86/Makefile": "core-$(CONFIG_KVM) += arch/x86/kvm/\n",
		"arch/x86/kernel/asm-offsets.c": `
#ifdef CONFIG_X86_32
#include "asm-offsets_32.c"
#else
#include "asm-offsets_64.c"
#endif
`,
		"arch/x86/kernel/asm-offsets_32.c": "", "arch/x86/kernel/asm-offsets_64.c": "", "kernel/bounds.c": "",
		"arch/x86/kvm/Makefile": "obj-$(CONFIG_KVM) += kvm.o\ntargets += kvm-asm-offsets.s\n",
		"arch/x86/kvm/kvm.c":    "", "arch/x86/kvm/kvm-asm-offsets.c": "",
	})
	expect(t, r, map[string]string{
		"kernel/bounds.c":                  "true",
		"arch/x86/kernel/asm-offsets.c":    "true",
		"arch/x86/kernel/asm-offsets_64.c": "!CONFIG_X86_32=y",
		"arch/x86/kvm/kvm-asm-offsets.c":   "CONFIG_KVM",
	})
}

// arch/x86/boot/startup renames its objects to %.pi.o, which a rule makes of
// %.o by prefixing the symbols; arm64's nVHE code uses %.nvhe.o the same way.
func TestRenamedObjects(t *testing.T) {
	r := crawl(t, dirTree(`
obj-$(CONFIG_A) += a.o
obj-y += b.o
obj-y := $(patsubst %.o,%.pi.o,$(obj-y))
obj-$(CONFIG_C) += c.nvhe.o
`, "a.c", "b.c", "c.c"))
	expect(t, r, map[string]string{"drivers/d/a.c": "CONFIG_A", "drivers/d/b.c": "true", "drivers/d/c.c": "CONFIG_C"})
}

// A rule with a recipe compiles an object of its directory from a source
// elsewhere: xe builds i915's display code, libstub lib/ code under a
// renamed object, rust/ its kernel crate from kernel/lib.rs, lkdtm an
// objcopied object from another object of the directory. Rules without a
// recipe only add prerequisites, and target-specific variables are not
// rules.
func TestRules(t *testing.T) {
	files := dirTree(`
xe-$(CONFIG_D) += i915-display/a.o
obj-$(CONFIG_XE) += xe.o
obj-$(CONFIG_RO) += ro_objcopy.o
$(obj)/ro_objcopy.o: $(obj)/ro.o FORCE
	$(call if_changed,objcopy)
lib-y := lib-ctype.o
lib-y := $(patsubst %.o,%.stub.o,$(lib-y))
obj-y += kernel.o own.o gen.o
ifdef CONFIG_R
obj-y += cond.o
$(obj)/cond.o: $(srctree)/lib/cond.c ; $(call if_changed_rule,cc_o_c)
endif
$(obj)/i915-display/%.o: $(srctree)/drivers/i915/display/%.c FORCE
	$(call if_changed_rule,cc_o_c)

$(obj)/lib-%.o: $(srctree)/lib/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/kernel.o: private flags = $(src)/other.c
$(obj)/kernel.o: $(src)/kernel/lib.rs $(obj)/other.o FORCE
	$(call if_changed_rule,rustc_library)
$(obj)/gen.o: $(srctree)/lib/prereq.c
$(obj)/%.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
obj-y += alt/x.o
ifdef CONFIG_ALT
$(obj)/alt/%.o: $(srctree)/lib/alt/%.c
	$(call if_changed_rule,cc_o_c)
endif
$(obj)/alt/%.o: $(srctree)/lib/base/%.c
	$(call if_changed_rule,cc_o_c)
`, "kernel/lib.rs", "other.c", "own.c", "ro.c")
	for _, f := range []string{"drivers/i915/display/a.c", "lib/ctype.c", "lib/cond.c", "lib/prereq.c", "lib/alt/x.c", "lib/base/x.c"} {
		files[f] = ""
	}
	r := crawl(t, files)
	expect(t, r, map[string]string{
		"drivers/i915/display/a.c": "(CONFIG_D=m && CONFIG_XE=m) || (CONFIG_D=y && CONFIG_XE)",
		"lib/ctype.c":              "true",
		"lib/cond.c":               "CONFIG_R",
		"drivers/d/kernel/lib.rs":  "true",
		"drivers/d/own.c":          "true",
		"drivers/d/ro.c":           "CONFIG_RO",
		"drivers/d/other.c":        "",
		"lib/prereq.c":             "",
		// A rule under a condition leaves the next one where it does
		// not hold.
		"lib/alt/x.c":  "CONFIG_ALT",
		"lib/base/x.c": "!CONFIG_ALT",
	})
}

// A conditional inside a recipe leaves the recipe going, so its command
// lines assign nothing; a target-specific variable takes no recipe, so the
// indented assignment after it counts, as in v3.10's x86 boot/compressed.
func TestRecipeConditionals(t *testing.T) {
	files := dirTree(`
obj-y += foo.o a.o $(objs)
$(obj)/foo.o: $(srctree)/lib/foo.c
ifdef CONFIG_X
	$(MAKE) -C tools obj-y=b.o
else
	$(call cmd,a)
endif
$(obj)/t.o: KBUILD_CFLAGS += -DX
ifdef CONFIG_Y
	objs += tv.o
endif
`, "a.c", "b.c", "tv.c")
	files["lib/foo.c"] = ""
	expect(t, crawl(t, files), map[string]string{
		"lib/foo.c":      "true",
		"drivers/d/a.c":  "true",
		"drivers/d/b.c":  "",
		"drivers/d/tv.c": "CONFIG_Y",
	})
}

// Each rule is tried once for an object, so the second of two conditional
// rules holds where the first does not, and the source compiles once.
func TestRulesTriedOnce(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile": "drivers-y := drivers/\n",
		"drivers/Makefile": `
obj-y += foo.o
ifdef CONFIG_A
$(obj)/%.o: $(srctree)/x/%.c
	$(cmd)
endif
ifdef CONFIG_B
$(obj)/%.o: $(srctree)/y/%.c
	$(cmd)
endif
`,
		"x/foo.c": "", "y/foo.c": "",
	})
	expect(t, r, map[string]string{"x/foo.c": "CONFIG_A", "y/foo.c": "!CONFIG_A && CONFIG_B"})
	if n := len(r.compiled["y/foo.c"]); n != 1 {
		t.Errorf("y/foo.c compiles %d times, want 1", n)
	}
}

// A static pattern rule maps each of its targets to a source, as the
// powerpc vDSO builds gettimeofday-32.o from gettimeofday.S.
func TestStaticPatternRules(t *testing.T) {
	files := dirTree(`
objs = a-32.o b-32.o
objs := $(addprefix $(obj)/, $(objs))
obj-y += a-32.o b-32.o c-32.o crt-32.o
$(objs): %-32.o: %.S FORCE
	$(call if_changed_dep,as)
$(obj)/c-32.o: %-32.o: %.c FORCE
	$(call if_changed_dep,cc)
$(obj)/crt-32.o: %-32.o: $(srctree)/lib/crt.S FORCE
	$(call if_changed_dep,as)
`, "a.S", "b.S", "c.c")
	files["lib/crt.S"] = ""
	expect(t, crawl(t, files), map[string]string{"drivers/d/a.S": "true", "drivers/d/b.S": "true", "drivers/d/c.c": "true", "lib/crt.S": "true"})
}

// Variables the arch Makefile exports, such as powerpc's BITS, reach
// every directory's Makefile.
func TestExportedVariables(t *testing.T) {
	r, err := Crawl(tree(map[string]string{
		"Makefile": "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/powerpc/Makefile": `
ifdef CONFIG_PPC64
BITS := 64
else
BITS := 32
endif
export BITS
export KEXEC := kexec/
LOCAL := local.o
core-y += arch/powerpc/kernel/
`,
		"arch/powerpc/kernel/Makefile":       "obj-y += entry_$(BITS).o $(LOCAL)\nobj-$(CONFIG_KEXEC_CORE) += $(KEXEC)\n",
		"arch/powerpc/kernel/kexec/Makefile": "obj-y += core_$(BITS).o\n",
		"arch/powerpc/kernel/entry_32.S":     "", "arch/powerpc/kernel/entry_64.S": "", "arch/powerpc/kernel/local.c": "",
		"arch/powerpc/kernel/kexec/core_64.c": "",
	}), Options{Arch: "powerpc"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, r, map[string]string{
		"arch/powerpc/kernel/entry_64.S":      "CONFIG_PPC64",
		"arch/powerpc/kernel/entry_32.S":      "!CONFIG_PPC64",
		"arch/powerpc/kernel/kexec/core_64.c": "CONFIG_KEXEC_CORE=y && CONFIG_PPC64", // kexec/ is linked where obj-y lists it
		// Only exported variables cross into other Makefiles.
		"arch/powerpc/kernel/local.c": "",
	})
}

// A directory without a Makefile is not a build directory: its files are
// #included by a unit above it, as kernel/sched/ext/ext.c is, so their
// condition is unknown until an #include gives one. A directory with a
// Makefile that no parent lists is not built.
func TestDirectoryWithoutMakefile(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":                    "core-y += kernel/\ndrivers-y += drivers/\n",
		"kernel/Makefile":             "obj-y += sched/\n",
		"kernel/sched/Makefile":       "obj-y += build_policy.o\n",
		"kernel/sched/build_policy.c": "", "kernel/sched/ext/ext.c": "",
		"drivers/Makefile":      "obj-$(CONFIG_PCI) += pci/\n",
		"drivers/s390/Makefile": "obj-y += cio.o\n",
		"drivers/s390/cio.c":    "",
	})
	if _, st := r.Lookup("kernel/sched/ext/ext.c"); st != Unlisted {
		t.Errorf("kernel/sched/ext/ext.c: %v, want unlisted", st)
	}
	if _, st := r.Lookup("drivers/s390/cio.c"); st != NotBuilt {
		t.Errorf("drivers/s390/cio.c: %v, want not built", st)
	}
}

func TestBrokenMakefile(t *testing.T) {
	// One unbalanced Makefile is reported and skipped; the rest is crawled.
	r := crawl(t, map[string]string{
		"Makefile":              "drivers-y := drivers/\n",
		"drivers/Makefile":      "obj-y += bad/ good/\n",
		"drivers/bad/Makefile":  "ifdef CONFIG_X\nobj-y += bad.o\n",
		"drivers/bad/bad.c":     "",
		"drivers/good/Makefile": "obj-y += good.o\nendif\nobj-y += good2.o\n$(eval obj-y += good3.o ${)\n",
		"drivers/good/good.c":   "",
		"drivers/good/good2.c":  "",
	})
	if len(r.Errors) != 3 {
		t.Errorf("Errors = %q, want three", r.Errors)
	}
	expect(t, r, map[string]string{"drivers/good/good.c": "true", "drivers/good/good2.c": "true"})
}

// A stray endif in an included file is noted and closes nothing: as in
// make, a file's conditionals end in that file.
func TestIncludedStrayEndif(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":         "drivers-y := drivers/\nifdef CONFIG_A\ninclude frag.mk\nendif\n",
		"frag.mk":          "endif\nendif\ndrivers-y += extra/\n",
		"drivers/Makefile": "obj-y += a.o\n",
		"drivers/a.c":      "",
		"extra/Makefile":   "obj-y += b.o\n",
		"extra/b.c":        "",
	})
	expect(t, r, map[string]string{"drivers/a.c": "true", "extra/b.c": "CONFIG_A"})
	if n := len(slices.DeleteFunc(slices.Clone(r.Errors), func(e string) bool {
		return !strings.Contains(e, "frag.mk") || !strings.Contains(e, "endif without a conditional")
	})); n != 2 {
		t.Errorf("Errors = %q, want two stray endifs in frag.mk", r.Errors)
	}
}

func TestCrawlNeedsTopMakefile(t *testing.T) {
	if _, err := Crawl(fstest.MapFS{}, Options{Arch: "x86"}); !errors.Is(err, ErrNoMakefile) {
		t.Errorf("Crawl of an empty tree: %v, want ErrNoMakefile", err)
	}
}

// The patterns of a substitution reference are expanded, as loongarch's
// $(obj-vdso-y:%.o=$(obj)/%.o) needs.
func TestSubstitutionReference(t *testing.T) {
	r := crawl(t, dirTree(`
PFX := sub/
V := a.o b.o
obj-y += $(V:%.o=$(PFX)%.o) $(V:.o=-x.o)
`, "sub/a.c", "sub/b.c", "a-x.c"))
	expect(t, r, map[string]string{"drivers/d/sub/a.c": "true", "drivers/d/sub/b.c": "true", "drivers/d/a-x.c": "true"})
}

// The other arches build their vDSOs with their own rules: arm64 and
// powerpc enter the directory only through a wrapper object that includes
// the image, and name the objects in lists of their own; the generic code
// comes in with -include $(c-gettimeofday-y).
func TestArchVDSOs(t *testing.T) {
	vdsoInclude := `GENERIC_VDSO_MK_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
GENERIC_VDSO_DIR := $(dir $(GENERIC_VDSO_MK_PATH))
c-gettimeofday-$(CONFIG_GENERIC_GETTIMEOFDAY) := $(addprefix $(GENERIC_VDSO_DIR), gettimeofday.c)
`
	arm64, err := Crawl(tree(map[string]string{
		"Makefile":            "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/arm64/Makefile": "core-y += arch/arm64/kernel/\n",
		"arch/arm64/kernel/Makefile": `
obj-y += vdso-wrap.o
obj-$(CONFIG_COMPAT_VDSO) += vdso32-wrap.o
$(obj)/vdso-wrap.o: $(obj)/vdso/vdso.so
`,
		"arch/arm64/kernel/vdso/Makefile": `
include $(srctree)/lib/vdso/Makefile.include
obj-vdso := vgettimeofday.o note.o
targets := $(obj-vdso) vdso.so vdso.so.dbg
obj-vdso := $(addprefix $(obj)/, $(obj-vdso))
ifneq ($(c-gettimeofday-y),)
  CFLAGS_vgettimeofday.o += -include $(c-gettimeofday-y)
endif
`,
		"arch/arm64/kernel/vdso32/Makefile": "c-obj-vdso := note.o\nobj-vdso := $(addprefix $(obj)/, $(c-obj-vdso))\n",
		"lib/vdso/Makefile.include":         vdsoInclude,
		"arch/arm64/kernel/vdso-wrap.S":     "", "arch/arm64/kernel/vdso32-wrap.S": "",
		"arch/arm64/kernel/vdso/vgettimeofday.c": "", "arch/arm64/kernel/vdso/note.S": "",
		"arch/arm64/kernel/vdso32/note.c": "", "lib/vdso/gettimeofday.c": "",
	}), Options{Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, arm64, map[string]string{
		"arch/arm64/kernel/vdso/vgettimeofday.c": "true",
		"arch/arm64/kernel/vdso/note.S":          "true",
		"arch/arm64/kernel/vdso32/note.c":        "CONFIG_COMPAT_VDSO",
		"lib/vdso/gettimeofday.c":                "CONFIG_GENERIC_GETTIMEOFDAY=y",
	})
	powerpc, err := Crawl(tree(map[string]string{
		"Makefile":              "include $(srctree)/arch/$(SRCARCH)/Makefile\n",
		"arch/powerpc/Makefile": "core-y += arch/powerpc/kernel/\n",
		"arch/powerpc/kernel/Makefile": `
obj-$(CONFIG_VDSO32) += vdso32_wrapper.o
obj-$(CONFIG_PPC64) += vdso64_wrapper.o
`,
		"arch/powerpc/kernel/vdso/Makefile": `
obj-vdso32 = gettimeofday-32.o
obj-vdso64 = gettimeofday-64.o
targets := $(obj-vdso32) vdso32.so.dbg vgettimeofday-32.o
obj-vdso32 := $(addprefix $(obj)/, $(obj-vdso32))
targets += $(obj-vdso64) vdso64.so.dbg vgettimeofday-64.o
obj-vdso64 := $(addprefix $(obj)/, $(obj-vdso64))
$(obj-vdso32): %-32.o: %.S FORCE
	$(call if_changed_dep,vdso32as)
$(obj)/vgettimeofday-32.o: %-32.o: %.c FORCE
	$(call if_changed_dep,vdso32cc)
$(obj-vdso64): %-64.o: %.S FORCE
	$(call if_changed_dep,vdso64as)
$(obj)/vgettimeofday-64.o: %-64.o: %.c FORCE
	$(call if_changed_dep,cc_o_c)
`,
		"arch/powerpc/kernel/vdso32_wrapper.S": "", "arch/powerpc/kernel/vdso64_wrapper.S": "",
		"arch/powerpc/kernel/vdso/gettimeofday.S":  "",
		"arch/powerpc/kernel/vdso/vgettimeofday.c": "",
	}), Options{Arch: "powerpc"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, powerpc, map[string]string{
		"arch/powerpc/kernel/vdso/gettimeofday.S":  "CONFIG_PPC64 || CONFIG_VDSO32",
		"arch/powerpc/kernel/vdso/vgettimeofday.c": "CONFIG_PPC64 || CONFIG_VDSO32",
	})
}

// TestKbuildSemantics checks the crawler against Kbuild on the minimized
// Makefiles of testdata/kbuild: whether each object is built into the
// kernel, into a module or not at all, in each configuration a Makefile's
// header lists, as testdata/kbuild/check.sh records it from
// scripts/Makefile.build of v7.2.
func TestKbuildSemantics(t *testing.T) {
	data, err := os.ReadFile("testdata/kbuild/expected.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}   // case, config and object to state
	objs := map[string][]string{} // objects by case
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Split(l, "\t")
		want[f[0]+"|"+f[1]+"|"+f[2]] = f[3]
		if !slices.Contains(objs[f[0]], f[2]) {
			objs[f[0]] = append(objs[f[0]], f[2])
		}
	}
	for name, names := range objs {
		mk, err := os.ReadFile("testdata/kbuild/" + name + ".mk")
		if err != nil {
			t.Fatal(err)
		}
		var srcs []string
		for _, o := range names {
			srcs = append(srcs, strings.TrimSuffix(o, ".o")+".c")
		}
		r := crawl(t, dirTree(string(mk), srcs...))
		_, cfgs, _ := strings.Cut(string(mk), "# configs: ")
		cfgs, _, _ = strings.Cut(cfgs, "\n")
		for _, cfg := range strings.Split(cfgs, ";") {
			c := kcond.Config{}
			for _, kv := range strings.Fields(cfg) {
				k, v, _ := strings.Cut(kv, "=")
				c[k] = v[0]
			}
			for _, o := range names {
				p := "drivers/d/" + strings.TrimSuffix(o, ".o") + ".c"
				got := "none"
				if e, st := r.Lookup(p); st == Built && e.Eval(c) == kcond.True {
					builtin, module := r.Module(p)
					switch {
					case builtin.Eval(c) == kcond.True:
						got = "builtin"
					case module.Eval(c) == kcond.True:
						got = "module"
					default:
						got = "unknown"
					}
				}
				w := want[name+"|"+cfg+"|"+o]
				if w == "" {
					w = "none"
				}
				if got != w {
					t.Errorf("%s, %s: %s is %s, Kbuild builds it %s", name, cfg, o, got, w)
				}
			}
		}
	}
}

// TestLinks checks that each way a source is compiled keeps the object it
// goes into, which the OR of Files loses.
func TestLinks(t *testing.T) {
	r := crawl(t, map[string]string{
		"Makefile":         "drivers-y := drivers/\nnet-y := net/\n",
		"drivers/Makefile": "obj-y += d/\n",
		"drivers/d/Makefile": `
obj-$(CONFIG_FOO) += foo.o
obj-$(CONFIG_BAR) += bar.o
foo-$(CONFIG_A) += x.o
bar-$(CONFIG_B) += x.o
obj-$(CONFIG_P) += lp.o
obj-$(CONFIG_I) += incl.o
`,
		"drivers/d/x.c": "", "drivers/d/lp.c": "", "drivers/d/incl.c": "#include \"inc.c\"\n",
		"drivers/d/inc.c": "",
		"net/Makefile":    "obj-y += ipv6/\n",
		// A file obj-y lists under a guard on a module's option is still
		// built in: net/ipv6's mcast_snoop.o.
		"net/ipv6/Makefile": "obj-$(CONFIG_IPV6) += ipv6.o\nipv6-y := af_inet6.o\n" +
			"ifneq ($(CONFIG_IPV6),)\nobj-y += mcast_snoop.o\nendif\n",
		"net/ipv6/af_inet6.c": "", "net/ipv6/mcast_snoop.c": "",
	})
	type link struct{ object, builtin, module string }
	for p, want := range map[string][]link{
		// One object, named by the object, not the source.
		"drivers/d/lp.c": {{"drivers/d/lp", "CONFIG_P=y", "CONFIG_P=m"}},
		// One source, two composites: one link each, by its own option.
		"drivers/d/x.c": {
			{"drivers/d/foo", "CONFIG_A=y && CONFIG_FOO=y", "CONFIG_A && CONFIG_FOO=m"},
			{"drivers/d/bar", "CONFIG_B=y && CONFIG_BAR=y", "CONFIG_B && CONFIG_BAR=m"},
		},
		"net/ipv6/af_inet6.c": {{"net/ipv6/ipv6", "CONFIG_IPV6=y", "CONFIG_IPV6=m"}},
		// Built in with CONFIG_IPV6=m, though its gate tests only CONFIG_IPV6.
		"net/ipv6/mcast_snoop.c": {{"net/ipv6/mcast_snoop", "CONFIG_IPV6", "false"}},
		// #included into incl.o, which Links can't name: no links at all.
		"drivers/d/inc.c": nil,
	} {
		var got []link
		for _, l := range r.Links(p) {
			got = append(got, link{l.Object, l.Builtin.String(), l.Module.String()})
		}
		slices.SortFunc(got, func(a, b link) int { return strings.Compare(b.object, a.object) })
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", p, got, want)
		}
	}
}
