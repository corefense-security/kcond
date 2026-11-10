// Package gate answers Trowl's question about a kernel tree: which config
// gates compile the files a CVE record names. A Tree reads the tree and the
// build once, so that the thousands of CVEs of a scan each cost a map lookup.
package gate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
	"github.com/corefense-security/kcond/change"
	"github.com/corefense-security/kcond/gitfs"
	"github.com/corefense-security/kcond/kbuild"
)

// Skipped is the status of a file the kernel build compiles nothing from:
// Makefile, Kconfig, documentation, tools and scripts. It says nothing about
// the build; the other statuses are those of builds.
const Skipped = "skipped"

// File is one file of a CVE record as the build reads it.
type File struct {
	Path string
	// Status is builds.StatusBuilt, StatusNotBuilt, StatusHeader,
	// StatusUnlisted, StatusMissing or Skipped.
	Status string
	// Gate is the condition that compiles the file, in the syntax
	// kcond.Parse reads; it is set when Status is built.
	Gate string
	// Links are the objects a Makefile compiles the file into, which say
	// where its code goes once Gate holds: into vmlinux or into a module.
	// Gate is the OR of their conditions, and it alone says whether the
	// file is compiled (see kbuild.Link). Links is empty for a header and
	// for a source another file #includes, whose objects aren't known.
	Links []Link
	// DirGate is set for a source the tree lacks (StatusMissing), such as
	// one added after this release: the OR of the gates of the sources the
	// tree has in its directory, "" when it has none there. Where it is
	// false, the directory compiles nothing in this build, and a source
	// added to it later would be compiled no more than its neighbours.
	DirGate string
}

// Link is one object a Makefile compiles a file into. Builtin and Module
// are conditions in the syntax kcond.Parse reads, written plainly as Gate
// is, so a bool option has no =m test.
type Link struct {
	// Object is the object without .o, from the top of the tree, such as
	// net/sctp/sctp. As a module it is kernel/net/sctp/sctp.ko under
	// /lib/modules/<release>/.
	Object string
	// Builtin is when the object is linked into vmlinux, Module when it
	// is built as a module.
	Builtin, Module string
}

// links returns the objects source p is compiled into in t's build. A way
// of compiling it that has no object, such as a .lds linker script, can't
// be placed, so the file then has no links at all: one left out would let
// the others decide where its code goes.
func (t *Tree) links(p string) []Link {
	var out []Link
	for _, l := range t.build.Kbuild.Links(p) {
		if l.Object == "" {
			return nil
		}
		out = append(out, Link{Object: l.Object,
			Builtin: t.build.Plain(l.Builtin).String(), Module: t.build.Plain(l.Module).String()})
	}
	return out
}

// Tree is one build of a kernel tree, read once.
type Tree struct {
	// Dir is the directory the tree was opened at, and Version the release
	// its Makefile names, such as 6.18.52.
	Dir, Version string
	fsys         fs.FS
	build        builds.Build

	mu       sync.Mutex
	dirGates map[string]string // dirGate's results, by directory
}

// dirGate is the OR of the gates of the C and assembly sources directly in
// dir (not in its subdirectories), written plainly, or "" when the build
// lists none there.
//
// Kbuild compiles a source only when some Makefile lists it: its own
// directory's, once the build descends into it, or another's, by a relative
// path (amdgpu lists ../display/ files). Either way its neighbours show it:
// when none of them is compiled, the directory isn't descended into and no
// other Makefile reaches into it. A source added there later is then not
// compiled either, unless the Makefile change that added it also hooked the
// directory up some new way, which a fix doesn't do.
func (t *Tree) dirGate(dir string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if g, ok := t.dirGates[dir]; ok {
		return g
	}
	var terms []*kcond.Expr
	for p, e := range t.build.Kbuild.Files {
		if ext := path.Ext(p); path.Dir(p) == dir && (ext == ".c" || ext == ".S") {
			terms = append(terms, e)
		}
	}
	g := ""
	if len(terms) > 0 {
		g = t.build.Plain(kcond.Or(terms...)).String()
	}
	if t.dirGates == nil {
		t.dirGates = map[string]string{}
	}
	t.dirGates[dir] = g
	return g
}

// Open reads the tree at dir as the build named build reads it, one of
// builds.ConfigBuilds.
func Open(ctx context.Context, dir, build string) (*Tree, error) {
	fsys := filesystem(ctx, dir)
	if st, err := fs.Stat(fsys, "arch"); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a kernel tree: it has no arch/", dir)
	}
	b, ok := builds.Named(fsys, build, nil)
	if !ok {
		return nil, fmt.Errorf("the tree has no %s build", build)
	}
	if b.Kbuild == nil {
		return nil, fmt.Errorf("the Makefiles of the %s build could not be read: %w", build, b.Err)
	}
	version, err := release(fsys)
	if err != nil {
		return nil, err
	}
	return &Tree{Dir: dir, Version: version, fsys: fsys, build: b}, nil
}

// filesystem reads a checkout through git when git can, as its grep makes
// the #include scan fast. A container often has no git, or won't trust a
// mounted tree of another user; the plain directory reads the same files.
func filesystem(ctx context.Context, dir string) fs.FS {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run() == nil {
			return gitfs.WorkTree(ctx, dir)
		}
	}
	return os.DirFS(dir)
}

var releaseLine = regexp.MustCompile(`(?m)^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\d+)\s*$`)

// release reads the kernel release from the top Makefile.
func release(fsys fs.FS) (string, error) {
	data, err := fs.ReadFile(fsys, "Makefile")
	if err != nil {
		return "", err
	}
	parts := map[string]string{}
	for _, m := range releaseLine.FindAllSubmatch(data, -1) {
		if _, seen := parts[string(m[1])]; !seen {
			parts[string(m[1])] = string(m[2])
		}
	}
	if parts["VERSION"] == "" || parts["PATCHLEVEL"] == "" {
		return "", errors.New("the top Makefile names no kernel version")
	}
	v := parts["VERSION"] + "." + parts["PATCHLEVEL"]
	if s := parts["SUBLEVEL"]; s != "" {
		v += "." + s
	}
	return v, nil
}

// Files gives the status and gate of each path.
func (t *Tree) Files(paths []string) []File {
	out := make([]File, len(paths))
	for i, p := range paths {
		out[i] = t.file(p)
	}
	return out
}

func (t *Tree) file(p string) File {
	// Before anything else: even a Kconfig of another architecture says
	// that this build doesn't read it.
	if pa := builds.PathArch(p); pa != "" && pa != t.build.Arch {
		return File{Path: p, Status: builds.StatusNotBuilt}
	}
	kernel, header := change.Kernel(p)
	if !kernel {
		return File{Path: p, Status: Skipped}
	}
	// A record names a file as it was when the bug was fixed. One this tree
	// lacks may be gone, or moved here under another name, so nothing can be
	// said of it by itself; its directory may say something (see dirGate).
	if _, err := fs.Stat(t.fsys, p); err != nil {
		f := File{Path: p, Status: builds.StatusMissing}
		if !header {
			f.DirGate = t.dirGate(path.Dir(p))
		}
		return f
	}
	fc := builds.BuildCond(p, header, kcond.Const(true), t.build)
	f := File{Path: p, Status: fc.Status}
	if fc.Kbuild != nil {
		f.Gate = fc.Kbuild.String()
		f.Links = t.links(p)
	}
	return f
}

// flagHeaders are the headers the top Makefile hands every object with
// -include, which no #include names.
var flagHeaders = []string{"include/linux/compiler-version.h", "include/linux/kconfig.h", "include/linux/compiler_types.h"}

var includeLine = regexp.MustCompile(`^\s*#\s*include\s*([<"])([^">]+)[">]`)

// Compiled returns the files the sources cfg compiles include, directly or
// not, each with the source that reached it first: the headers a build reads,
// which no Makefile lists. An #include under an #if that cfg rules out doesn't
// count; one that depends on anything else does, as a header missed reads as
// not compiled, and a file reached in vain only keeps a CVE open.
func (t *Tree) Compiled(cfg kcond.Config) (map[string]string, error) {
	kept := func(e *kcond.Expr) bool { return t.build.Plain(e).Eval(cfg) != kcond.False }
	search := t.searchPaths(t.build.Kbuild.IncludeDirs(kept))
	reached := map[string]string{}
	var queue []string
	visit := func(p, from string) {
		if _, seen := reached[p]; !seen {
			reached[p] = from
			queue = append(queue, p)
		}
	}
	for p, e := range t.build.Kbuild.Files {
		if kept(e) {
			visit(p, p)
		}
	}
	for _, h := range flagHeaders {
		visit(h, "the kernel's -include flags")
	}
	for len(queue) > 0 {
		p := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		data, err := fs.ReadFile(t.fsys, p)
		if errors.Is(err, fs.ErrNotExist) {
			continue // a generated file
		}
		if err != nil {
			return nil, err
		}
		// Unbalanced directives leave every line unconditional.
		cpp, _ := kcond.Lines(data, kbuild.CodeOf(p))
		for i, line := range strings.Split(string(data), "\n") {
			m := includeLine.FindStringSubmatch(line)
			if m == nil || (i < len(cpp) && !kept(cpp[i])) {
				continue
			}
			if f := t.resolve(path.Dir(p), m[2], m[1] == `"`, search); f != "" {
				visit(f, reached[p])
			}
		}
	}
	return reached, nil
}

// searchPaths is where an #include looks, in order: the kernel's own
// directories, then the -I flags of single objects. Those are shared here
// though each holds for its object, which can only reach more.
func (t *Tree) searchPaths(dirs []string) []string {
	arch := "arch/" + t.build.Kbuild.Arch + "/include"
	return append([]string{"include", "include/uapi", arch, arch + "/uapi"}, dirs...)
}

// resolve finds the file an #include names: for a quoted name next to the
// including file first, and last in the directories above it, as Kbuild's
// -I$(src) and -I$(srctree) find it. "" is a generated file.
func (t *Tree) resolve(dir, name string, quoted bool, search []string) string {
	var candidates []string
	if quoted {
		candidates = append(candidates, path.Join(dir, name))
	}
	for _, d := range search {
		candidates = append(candidates, path.Join(d, name))
	}
	if rest, ok := strings.CutPrefix(name, "asm/"); ok {
		// Kbuild generates a wrapper for each asm header the arch lacks.
		candidates = append(candidates, "include/asm-generic/"+rest, "include/uapi/asm-generic/"+rest)
	}
	for d := dir; quoted && d != "." && d != "/"; d = path.Dir(d) {
		candidates = append(candidates, path.Join(path.Dir(d), name))
	}
	for _, c := range candidates {
		if st, err := fs.Stat(t.fsys, c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}
