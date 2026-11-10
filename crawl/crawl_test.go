package crawl

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func revParse(t *testing.T, dir, rev string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", rev).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// commitFile writes a file and commits it, returning the commit hash.
func commitFile(t *testing.T, dir, name, content, msg string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", name)
	git(t, dir, "commit", "-q", "-m", msg)
	return revParse(t, dir, "HEAD")
}

func newKernel(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	kernel := filepath.Join(t.TempDir(), "linux")
	git(t, t.TempDir(), "init", "-q", "-b", "master", kernel)
	return kernel
}

// A file is looked up at its revisions in order; a source no revision has
// is missing, a header nothing includes keeps its status, and one a listed
// source includes is built with it.
func TestResolve(t *testing.T) {
	kernel := newKernel(t)
	commitFile(t, kernel, "Makefile", "core-y := lib/\n", "kbuild")
	commitFile(t, kernel, "arch/x86/Kconfig", "config X86\n\tdef_bool y\n\nconfig A\n\tbool \"a\"\n", "x86")
	commitFile(t, kernel, "lib/Makefile", "obj-$(CONFIG_A) += a.o\nobj-y += b.o\n", "lib")
	commitFile(t, kernel, "lib/a.h", "int ah;\n", "a.h")
	c1 := commitFile(t, kernel, "lib/a.c", "#include \"a.h\"\nint a;\n", "a")
	c2 := commitFile(t, kernel, "lib/b.c", "int b;\n", "b")
	tr := kcond.Const(true)
	files := []*File{
		{Path: "lib/a.c", Region: tr, Revs: []string{c2, c1}},
		{Path: "lib/b.c", Region: tr, Revs: []string{c1, c2}},
		{Path: "lib/c.c", Region: tr, Revs: []string{c1, c2}},
		{Path: "include/x.h", Header: true, Region: tr, Revs: []string{c1}},
		{Path: "arch/arm/x.h", Header: true, Region: tr, Revs: []string{c1}},
		{Path: "lib/a.h", Header: true, Region: tr, Revs: []string{c1}},
	}
	var crawled int
	got, err := Resolve(context.Background(), kernel, files, Options{Workers: 2, Progress: func(n int) { crawled = n }})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []struct{ rev, status, kbuild string }{
		{c2, builds.StatusBuilt, "CONFIG_A"}, {c2, builds.StatusBuilt, "true"}, {"", builds.StatusMissing, ""},
		{"", builds.StatusHeader, ""}, {"", builds.StatusNotBuilt, ""}, {c1, builds.StatusBuilt, "CONFIG_A"},
	} {
		r := got[i]
		kb := ""
		if r.Cond.Kbuild != nil {
			kb = r.Cond.Kbuild.String()
		}
		if r.Rev != want.rev || r.Cond.Status != want.status || kb != want.kbuild {
			t.Errorf("%s: rev %q status %q kbuild %q; want %q %q %q", files[i].Path, r.Rev, r.Cond.Status, kb, want.rev, want.status, want.kbuild)
		}
	}
	if arches, _ := got[0].Arches.Lists(); len(arches) != 1 || arches[0] != "x86" {
		t.Errorf("a.c arches = %v, want x86", arches)
	}
	// Round one reads c1 and c2; b.c and c.c then move on to c2 again.
	if crawled != 3 {
		t.Errorf("crawled %d revisions, want 3", crawled)
	}
	// With a build, only that one is read: the same condition, no arches.
	one, err := Resolve(context.Background(), kernel, files[:1], Options{Build: builds.X86_64Build})
	if err != nil {
		t.Fatal(err)
	}
	if arches, _ := one[0].Arches.Lists(); one[0].Cond.Kbuild == nil || one[0].Cond.Kbuild.String() != "CONFIG_A" || len(arches) != 0 {
		t.Errorf("a.c in x86_64 only: kbuild %v arches %v; want CONFIG_A and none", one[0].Cond.Kbuild, arches)
	}
}

// A crawl that fails for a reason other than a missing top-level Makefile
// is an error, not a revision without the files.
func TestRevGrepError(t *testing.T) {
	kernel := newKernel(t)
	commitFile(t, kernel, "Makefile", "core-y := lib/\n", "kbuild")
	commitFile(t, kernel, "lib/Makefile", "obj-y += a.o\n", "lib")
	commitFile(t, kernel, "lib/a.c", "int a;\n", "a")
	commitFile(t, kernel, "lib/b.c", "#include \"a.c\"\n", "b")
	// git grep reads lib/b.c, which the crawl does not otherwise read.
	oid := revParse(t, kernel, "HEAD:lib/b.c")
	if err := os.Remove(filepath.Join(kernel, ".git", "objects", oid[:2], oid[2:])); err != nil {
		t.Fatal(err)
	}
	files := []*File{{Path: "lib/a.c", Region: kcond.Const(true)}}
	if found, err := Rev(context.Background(), kernel, "HEAD", files, ""); err == nil {
		t.Errorf("Rev = %v, nil; want the git grep error", found)
	}
	if _, err := Resolve(context.Background(), kernel, []*File{{Path: "lib/a.c", Region: kcond.Const(true), Revs: []string{"HEAD"}}}, Options{}); err == nil {
		t.Error("Resolve succeeded; want the git grep error")
	}
}

// Before v2.6.24 the x86-64 build compiled some of arch/i386, so a header
// there is built where the sources including it are, as in the other
// builds, not another architecture's file.
func TestResolveSplitX86(t *testing.T) {
	kernel := newKernel(t)
	commitFile(t, kernel, "Makefile", "include $(srctree)/arch/$(SRCARCH)/Makefile\n", "kbuild")
	commitFile(t, kernel, "arch/x86_64/Kconfig", "config X86_64\n\tdef_bool y\n\nconfig MTRR\n\tbool \"mtrr\"\n", "x86_64")
	commitFile(t, kernel, "arch/x86_64/Makefile", "core-y += arch/x86_64/kernel/\n", "x86_64")
	commitFile(t, kernel, "arch/x86_64/kernel/Makefile", "obj-$(CONFIG_MTRR) += ../../i386/kernel/cpu/mtrr/\n", "x86_64")
	commitFile(t, kernel, "arch/i386/Kconfig", "config X86_32\n\tdef_bool y\n", "i386")
	commitFile(t, kernel, "arch/i386/kernel/cpu/mtrr/Makefile", "obj-y += main.o\n", "mtrr")
	commitFile(t, kernel, "arch/i386/kernel/cpu/mtrr/main.c", "#include \"mtrr.h\"\n", "mtrr")
	commitFile(t, kernel, "arch/i386/kernel/cpu/mtrr/mtrr.h", "int mtrr;\n", "mtrr")
	var files []*File
	for _, p := range []string{"arch/i386/kernel/cpu/mtrr/main.c", "arch/i386/kernel/cpu/mtrr/mtrr.h"} {
		files = append(files, &File{Path: p, Header: strings.HasSuffix(p, ".h"), Region: kcond.Const(true), Revs: []string{"HEAD"}})
	}
	got, err := Resolve(context.Background(), kernel, files, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"built CONFIG_MTRR", "built CONFIG_MTRR"} {
		s := got[i].Cond.Status
		if got[i].Cond.Kbuild != nil {
			s += " " + got[i].Cond.Kbuild.String()
		}
		if s != want {
			t.Errorf("%s: x86-64 condition %q, want %q", files[i].Path, s, want)
		}
	}
}
