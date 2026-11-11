// Package kbuild computes Kbuild presence conditions: the CONFIG_ settings
// under which each kernel source file is compiled for an architecture. It
// crawls the tree from the top-level Makefile, evaluating each Makefile
// with variables whose values are words present under conditions, the way
// cvehound's crawler descends the tree but with conditional values,
// composite objects and directory conditions taken from the Makefile that
// lists each directory. A .c or .S file a listed source #includes is
// compiled with it, under that source's condition, and so is a header,
// where the files that #include it are (see Result.Lookup).
package kbuild

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/corefense-security/kcond"
)

// Options selects what to crawl.
type Options struct {
	// Arch is the source architecture under arch/, such as "x86". For x86,
	// trees before v2.6.24 use arch/x86_64.
	Arch string
	// Bits is the x86 word size Makefiles name objects by ($(BITS)): 64
	// unless set to 32, which crawls the i386 build.
	Bits string
	// Includes are the tree's #include directives that name .c and .S
	// files and its Rust module declarations, as ScanIncludes finds them;
	// nil scans the tree while the Makefiles are crawled, so fsys is read
	// from two goroutines. They are the same in every build, so the crawls
	// of one tree can share a scan.
	Includes *Includes
	// Lookups are the files the caller will look up (see Result.Lookup):
	// when one is a header, the tree's #include lines are listed during
	// the crawl rather than at the first lookup, for the crawls sharing
	// its Includes as well.
	Lookups []string
}

// Status tells how a file relates to the build.
type Status uint8

const (
	// Built: a Makefile lists the file, or a listed source #includes it,
	// a header directly or through other headers; it is compiled when its
	// condition holds.
	Built Status = iota
	// Unlisted: no Makefile the crawl follows lists the file and no source
	// they list #includes it: the build enters its directory, as for a
	// file only a generated source includes, or the arch's own rules build
	// it, as for arch/arm/boot/compressed. A header is unlisted when no
	// listed file includes it (see Result.Lookup). Its condition is
	// unknown.
	Unlisted
	// NotBuilt: the file belongs to another architecture, is the twin of a
	// listed file for the other word size, or is outside arch/ in a
	// directory the build never enters.
	NotBuilt
	// NotSource: not a .c, .S, .rs or .h file.
	NotSource
)

func (s Status) String() string {
	return [...]string{"built", "unlisted", "not built", "not a source"}[s]
}

// Result holds the conditions of one tree.
type Result struct {
	Arch string // the arch/ directory used
	// Files maps each listed or #included source file to the condition
	// under which it is compiled.
	Files map[string]*kcond.Expr
	// Errors lists Makefile constructs that could not be evaluated.
	Errors []string
	// Includes are the #include directives the conditions of included
	// files were taken from, for other crawls of the tree to reuse.
	Includes *Includes

	reached map[string]bool
	bits    string          // x86 only
	makes   map[string]bool // directories with a Makefile or Kbuild
	// compiled lists how each listed source is compiled, with its
	// object's flags; includers are the #include edges into each file.
	compiled  map[string][]compilation
	includers map[string][]edge
	// subdirFlags holds each directory's subdir-ccflags-y and
	// subdir-asflags-y while the tree is crawled.
	subdirFlags map[string][2][]flag

	// A header is looked up when first asked about, in fsys; mu guards
	// the lookups, so Lookup, Module and Define are safe for concurrent
	// use. headers holds the condition of each header looked up, nil for
	// one found unlisted; Files keeps to the sources. roots finds the
	// files <...> names in the build's include directories, and included
	// lists by header the sources whose objects compile it through an
	// -include flag, made at the first lookup with defined, the macros
	// the -D flags of the objects define (see indexFlags). forced are the
	// -include flags of LINUXINCLUDE, which every object gets.
	fsys     fs.FS
	mu       sync.Mutex
	headers  map[string]*kcond.Expr
	parts    map[string][2]*kcond.Expr // a built header's condition in C and in assembly units
	roots    *includeRoots
	included map[string][]edge
	forced   []flag
	defined  map[string]bool
}

// flagKind tells what a compiler flag names.
type flagKind uint8

const (
	includeDir   flagKind = iota // -I or -iquote: a directory #include names are looked up in
	defineMacro                  // -D: a macro defined
	includedFile                 // -include: a file compiled ahead of the source
)

// flag is a -I directory, a -D macro or an -include file of an object's
// compiler flags, given under cond.
type flag struct {
	kind flagKind
	arg  string
	cond *kcond.Expr
}

// compilation is one way a source is compiled: under cond, into the
// kernel under builtin and into a module under module, as part of object,
// with flags.
type compilation struct {
	cond, builtin, module *kcond.Expr
	object                string // see listing.object, empty for a .lds or .s target
	flags                 []flag
}

// Link is one way a source is compiled, as Links returns it.
//
// Files[p] is the OR of the Cond of every Link of p. It says whether p is
// compiled at all, but not where it goes. Links keeps the ways apart:
//
//	obj-$(CONFIG_FOO) += foo.o     foo-$(CONFIG_A) += x.o
//	obj-$(CONFIG_BAR) += bar.o     bar-$(CONFIG_B) += x.o
//
//	Files["x.c"] = (CONFIG_FOO && CONFIG_A) || (CONFIG_BAR && CONFIG_B)
//	Links("x.c") = {Object: foo, Builtin: CONFIG_A=y && CONFIG_FOO=y, Module: CONFIG_A && CONFIG_FOO=m}
//	               {Object: bar, Builtin: CONFIG_B=y && CONFIG_BAR=y, Module: CONFIG_B && CONFIG_BAR=m}
//
// Builtin and Module can both be false where Cond holds. An extra-y or
// always-y object, or one in a directory only obj-m reaches, is compiled
// but neither linked into vmlinux nor made a module. So use Cond to tell
// whether the source is compiled. Builtin || Module can miss it.
type Link struct {
	// Object is the listed object without .o, from the top of the tree,
	// such as net/sctp/sctp. It is "" for a target that is not an object.
	Object string
	// Cond is when the source is compiled this way. Builtin is when the
	// object is then linked into vmlinux, and Module when it is built as
	// the module Object.ko. The conditions are as the crawl writes them,
	// so a bool option still has its =m test (see builds.Build.Plain).
	Cond, Builtin, Module *kcond.Expr
}

// Links returns the ways source p is compiled, one per object a Makefile
// lists it in. It returns nil for a file no Makefile lists. It also returns
// nil for a file another file #includes, such as a .c file #included into
// another. That code also goes into the includer's object, which Links
// can't name, so its links would understate where the file is built.
// Callers then have only the file's gate, which says whether it is
// compiled but not where.
func (r *Result) Links(p string) []Link {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.includers[p]) > 0 {
		return nil
	}
	var out []Link
	for _, c := range r.compiled[p] {
		out = append(out, Link{Object: c.object, Cond: c.cond, Builtin: c.builtin, Module: c.module})
	}
	return out
}

// Define returns the conditions under which source p is compiled with the
// macro x a -D flag of its object defines, and without it. A file a source
// #includes is compiled with that source's flags.
func (r *Result) Define(p, x string) (set, unset *kcond.Expr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// No object defines it: a region's #ifdef of a macro the headers
	// define asks about every header, so the answer is read off.
	if r.indexFlags(); !r.defined[x] {
		e, st := r.lookup(p)
		if st != Built {
			e = kcond.Const(false)
		}
		return kcond.Const(false), e
	}
	nodes, e, many := r.reach(p)
	if many {
		return e, e
	}
	return r.fold(p, nodes, func(c compilation) (*kcond.Expr, *kcond.Expr) {
		var fs []*kcond.Expr
		for _, f := range c.flags {
			if f.kind == defineMacro && f.arg == x {
				fs = append(fs, f.cond)
			}
		}
		with := kcond.Or(fs...)
		return kcond.And(c.cond, with), kcond.And(c.cond, kcond.Not(with))
	})
}

// fold ORs the two conditions f gives each compilation of source p, and
// each of a file that #includes p, there under the directive's condition,
// through the includers of the includers, nodes (see reach): the
// conditions propagate up the include graph as directory conditions do,
// each file once, where a header of thousands of includers has too many
// paths to follow.
func (r *Result) fold(p string, nodes map[string]bool, f func(compilation) (a, b *kcond.Expr)) (a, b *kcond.Expr) {
	ra, rb := map[string]*kcond.Expr{}, map[string]*kcond.Expr{}
	edges := map[string][]edge{}
	for n := range nodes {
		edges[n] = r.includers[n]
		for _, c := range r.compiled[n] {
			ca, cb := f(c)
			ra[n], rb[n] = orExpr(ra[n], ca), orExpr(rb[n], cb)
		}
	}
	a, b = kcond.Const(false), kcond.Const(false)
	if c, ok := dirConditions(ra, edges, false)[p]; ok {
		a = c
	}
	if c, ok := dirConditions(rb, edges, false)[p]; ok {
		b = c
	}
	return a, b
}

// Module returns the conditions under which source p is compiled into the
// kernel and into a module: obj-m lists its object and obj-y does not, as
// Kbuild filters obj-m by obj-y, it is a member of such a composite, or
// such a source includes it, and the other way round. A file compiled both
// ways, as one source compiled on its own and #included into a module's,
// has both. Each is false where it never holds.
func (r *Result) Module(p string) (builtin, module *kcond.Expr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodes, e, many := r.reach(p)
	if many {
		return e, kcond.And(e, kcond.Var("CONFIG_MODULES", kcond.Enabled))
	}
	return r.fold(p, nodes, func(c compilation) (*kcond.Expr, *kcond.Expr) { return c.builtin, c.module })
}

// maxFold bounds the sources whose compilations fold follows into a
// header.
const maxFold = 1000

// reach returns p and the files that include it, directly or through
// other files, a header looked up first, and for a header that more than
// maxFold compiled sources include, many and its condition.
// shortcut: the OR of the module or macro conditions of thousands of
// sources is as slow to build as it is long to read, so such a header
// reads as compiled either way wherever it is compiled, into a module
// where modules are built; refine if a change under #ifdef MODULE in a
// core header needs the exact condition.
func (r *Result) reach(p string) (nodes map[string]bool, e *kcond.Expr, many bool) {
	header := path.Ext(p) == ".h"
	st := Unlisted
	if header {
		e, st = r.lookup(p)
	}
	nodes = map[string]bool{p: true}
	for queue := []string{p}; len(queue) > 0; queue = queue[1:] {
		for _, in := range r.includers[queue[0]] {
			if !nodes[in.parent] {
				nodes[in.parent] = true
				queue = append(queue, in.parent)
			}
		}
	}
	if !header || st != Built {
		return nodes, nil, false
	}
	n := 0
	for f := range nodes {
		if r.compiled[f] != nil {
			n++
		}
	}
	return nodes, e, n > maxFold
}

// indexFlags indexes the objects' flags at the first header or macro
// lookup: by header, the sources compiling it through -include, every
// compiled source for the flags of LINUXINCLUDE; and the macros some -D
// flag defines.
func (r *Result) indexFlags() {
	if r.included != nil {
		return
	}
	r.included, r.defined = map[string][]edge{}, map[string]bool{}
	for src, cs := range r.compiled {
		if ext := path.Ext(src); ext == ".c" || ext == ".S" {
			for _, fl := range r.forced {
				r.included[fl.arg] = append(r.included[fl.arg], edge{src, fl.cond})
			}
		}
		for _, c := range cs {
			for _, f := range c.flags {
				switch {
				case f.kind == includedFile && path.Ext(f.arg) == ".h":
					r.included[f.arg] = append(r.included[f.arg], edge{src, f.cond})
				case f.kind == defineMacro:
					r.defined[f.arg] = true
				}
			}
		}
	}
}

// Lookup returns the condition of a source file or header. A header is
// built where the files that #include it are compiled, each under the
// condition of its directive's line, through other headers recursively:
// the OR over its includers, which the #include lines of the tree, listed
// at the first lookup, tell. A quoted name is found next to the including
// file, a bracketed one in the build's include directories (see
// includeRoots), either in the -I directories of the includer's object
// otherwise, and a header an -include flag names is included by the
// object's source, or by every one for the flags of LINUXINCLUDE. An
// includer that is not built, or that no Makefile lists, adds nothing, as
// for an included .c file. A header no listed file includes is unlisted.
func (r *Result) Lookup(p string) (*kcond.Expr, Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookup(p)
}

func (r *Result) lookup(p string) (*kcond.Expr, Status) {
	if path.Ext(p) == ".h" {
		return r.header(p)
	}
	if !slices.Contains(sourceExts, path.Ext(p)) {
		return nil, NotSource
	}
	if e, ok := r.Files[p]; ok {
		return e, Built
	}
	if rest, ok := strings.CutPrefix(p, "arch/"); ok {
		// arch/x86/um is user-mode Linux on an x86 host, another arch.
		if a, _, _ := strings.Cut(rest, "/"); a != r.Arch || strings.HasPrefix(rest, "x86/um/") {
			return nil, NotBuilt
		}
	}
	// Makefiles name x86 objects by $(BITS); the twin of a listed file
	// for the other word size is not built.
	if r.bits != "" {
		other := map[string]string{"64": "_32.", "32": "_64."}[r.bits]
		if i := strings.LastIndex(p, other); i >= 0 {
			if _, ok := r.Files[p[:i]+"_"+r.bits+"."+p[i+4:]]; ok {
				return nil, NotBuilt
			}
		}
	}
	if r.reached[path.Dir(p)] {
		return nil, Unlisted
	}
	// A directory without a Makefile is part of the nearest one above it
	// that has one: its files are #included or built by that Makefile's
	// own rules.
	for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
		if r.makes[d] {
			if r.reached[d] {
				return nil, Unlisted
			}
			break
		}
	}
	// The arch's own rules, not obj-y, reach directories such as
	// arch/arm/boot/compressed.
	if strings.HasPrefix(p, "arch/") {
		return nil, Unlisted
	}
	return nil, NotBuilt
}

// header looks a header up (see Lookup), memoizing the result in headers
// and includers. The includers are scanned a level at a time: the files
// including the header, then those including them. A header reached from
// no built source stays unlisted rather than not built. The C and the
// assembly units are kept apart, so that the __ASSEMBLY__ guards of the
// directives resolve.
func (r *Result) header(p string) (*kcond.Expr, Status) {
	if e, ok := r.headers[p]; ok {
		if e == nil {
			return nil, Unlisted
		}
		return e, Built
	}
	if r.fsys == nil {
		return nil, Unlisted
	}
	if r.roots == nil {
		r.roots = newIncludeRoots(r.fsys, r.Arch)
	}
	r.indexFlags()
	// roots are the conditions of the C and the assembly units reaching
	// p: the built sources, and the headers looked up before, whose
	// includers need no second scan.
	var roots [2]map[string]*kcond.Expr
	roots[0], roots[1] = map[string]*kcond.Expr{}, map[string]*kcond.Expr{}
	edges := map[string][]edge{}
	scanned := map[string]bool{p: true}
	// includer records that f includes h under cond: a header to scan
	// next, or a root.
	var next map[string]bool
	includer := func(h, f string, cond *kcond.Expr) {
		edges[h] = append(edges[h], edge{f, cond})
		if path.Ext(f) != ".h" {
			if e, st := r.lookup(f); st == Built {
				unit := 0
				if path.Ext(f) == ".S" {
					unit = 1
				}
				roots[unit][f] = e
			}
		} else if parts, ok := r.parts[f]; ok {
			roots[0][f], roots[1][f] = parts[0], parts[1]
		} else if _, done := r.headers[f]; !done && !scanned[f] {
			scanned[f] = true
			next[f] = true
		}
	}
	for level := map[string]bool{p: true}; len(level) > 0; {
		headers := slices.Sorted(maps.Keys(level))
		files, err := r.Includes.includers(r.fsys, headers)
		if err != nil {
			// shortcut: Lookup reports no error, so a read that fails
			// leaves the header unknown; report it if that misleads.
			r.headers[p] = nil
			return nil, Unlisted
		}
		next = map[string]bool{}
		bases := map[string]bool{}
		for _, h := range headers {
			bases[path.Base(h)] = true
		}
		for _, f := range slices.Sorted(maps.Keys(files)) {
			for _, d := range files[f] {
				if !bases[d.base] {
					continue
				}
				for _, t := range r.targets(f, d, level) {
					includer(t.file, f, t.cond)
				}
			}
		}
		for _, h := range headers {
			for _, e := range r.included[h] {
				includer(h, e.parent, e.cond)
			}
		}
		level = next
	}
	conds := map[string][2]*kcond.Expr{}
	for i, asm := range []bool{false, true} {
		es := map[string][]edge{}
		for h, in := range edges {
			for _, e := range in {
				es[h] = append(es[h], edge{e.parent, kcond.With(e.cond, kcond.AssemblyAtom, asm)})
			}
		}
		for h, c := range dirConditions(roots[i], es, false) {
			parts := conds[h]
			parts[i] = c
			conds[h] = parts
		}
	}
	for h := range scanned {
		if parts, ok := conds[h]; ok {
			for i, c := range parts {
				if c == nil {
					parts[i] = kcond.Const(false)
				}
			}
			// Module and Define fold over both units at once.
			in := make([]edge, len(edges[h]))
			for i, e := range edges[h] {
				in[i] = edge{e.parent, kcond.EitherUnit(e.cond)}
			}
			r.headers[h], r.parts[h], r.includers[h] = kcond.Or(parts[0], parts[1]), parts, in
		}
	}
	if c, ok := r.headers[p]; ok {
		return c, Built
	}
	r.headers[p] = nil
	return nil, Unlisted
}

// target is a file an #include names, under the condition of its line
// ANDed with that of the -I flag finding it.
type target struct {
	file string
	cond *kcond.Expr
}

// targets returns the headers of level that directive d of file f names.
func (r *Result) targets(f string, d incLine, level map[string]bool) []target {
	if d.quoted {
		if t, ok := resolveInclude(r.fsys, path.Dir(f), d.name); ok {
			if level[t] {
				return []target{{t, d.cond}}
			}
			return nil // another file of that name is nearer
		}
	}
	// The build's include directories come before an object's own -I
	// flags.
	if t, ok := r.roots.find(d.name); ok {
		if level[t] {
			return []target{{t, d.cond}}
		}
		return nil
	}
	// shortcut: a header has no object of its own, so the -I directories
	// of the objects including it are not searched for its directives.
	var out []target
	for _, t := range r.includeDirs(f, d.name, d.cond) {
		if level[t.file] {
			out = append(out, t)
		}
	}
	return out
}

// IncludeDirs lists the -I directories of the objects compiled under a
// condition keep accepts, for finding what their #include names mean.
func (r *Result) IncludeDirs(keep func(*kcond.Expr) bool) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, cs := range r.compiled {
		for _, c := range cs {
			for _, f := range c.flags {
				if f.kind == includeDir && !seen[f.arg] && keep(kcond.And(c.cond, f.cond)) {
					seen[f.arg] = true
					dirs = append(dirs, f.arg)
				}
			}
		}
	}
	slices.Sort(dirs)
	return dirs
}

// includeDirs returns the files the -I directories of the objects compiled
// from src give the #include name on a line under cond.
func (r *Result) includeDirs(src, name string, cond *kcond.Expr) []target {
	var out []target
	for _, c := range r.compiled[src] {
		for _, f := range c.flags {
			if f.kind == includeDir {
				out = append(out, target{path.Join(f.arg, name), kcond.And(cond, f.cond)})
			}
		}
	}
	return out
}

// rootLists are the top-level variables that hold the directories the
// build starts from.
var rootLists = []string{"init-y", "core-y", "drivers-y", "net-y", "libs-y", "virt-y"}

// kernelOnly reports whether the source p is compiled only into the kernel,
// at the configuration's word size, so that its arch macros follow Kconfig
// (see kcond.ParseIf). Headers are not, and neither is code a 64-bit
// configuration also compiles as 16- or 32-bit code: boot code, x86
// real-mode code, vDSOs (lib/vdso is part of them) and verify_cpu.S, which
// the real-mode trampoline includes.
func kernelOnly(p string) bool {
	if path.Ext(p) == ".h" || p == "arch/x86/kernel/verify_cpu.S" {
		return false
	}
	dirs := strings.Split(path.Dir(p), "/")
	if len(dirs) > 2 && dirs[0] == "arch" && dirs[2] == "boot" {
		return false
	}
	return !slices.ContainsFunc(dirs, func(d string) bool { return d == "realmode" || strings.HasPrefix(d, "vdso") })
}

// CodeOf tells how the file p is compiled (see kernelOnly): __ASSEMBLY__ is
// defined in .S files and not in C ones, and either way in headers, which
// both include.
func CodeOf(p string) kcond.Code {
	c := kcond.Code{Kernel: kernelOnly(p)}
	switch path.Ext(p) {
	case ".S":
		c.Assembly = kcond.True
	case ".h":
		c.Assembly = kcond.Unknown
	case ".rs":
		c.Rust = true
	}
	return c
}

// archDirs are the directories under arch/<arch> that the arch's own rules
// build in every configuration though no list names them: arch/x86/Makefile
// builds the boot image and the relocs tool, realmode/Makefile the
// real-mode blob.
var archDirs = map[string][]string{"x86": {"boot", "boot/compressed", "realmode/rm", "tools"}}

// programs are the lists of host and user programs, named without .o.
var programs = []string{"hostprogs", "hostprogs-y", "hostprogs-always-y", "userprogs", "userprogs-always-y"}

// ownList is an object list a Makefile links with its own rules. A gated
// list is linked into one of the gate objects, which are built when obj-y
// lists them, as the x86 vDSO's objects are linked into its images.
type ownList struct {
	name string
	gate []string
}

// vdso64 are the images of the 64-bit and x32 vDSOs, vdso.o and vdsox32.o
// before v3.16.
var vdso64 = []string{"vdso-image-64.o", "vdso-image-x32.o", "vdso.o", "vdsox32.o"}

// ownLists name, by directory, the object lists a Makefile links with its
// own rules rather than through obj-y; they are read like obj-y. Their
// words may carry the $(obj)/ prefix those rules need.
var ownLists = map[string][]ownList{
	"arch/x86/boot":              {{name: "setup-y"}},
	"arch/x86/boot/compressed":   {{name: "vmlinux-objs-y"}, {name: "VMLINUX_OBJS"}},
	"arch/x86/realmode/rm":       {{name: "realmode-y"}},
	"arch/x86/purgatory":         {{name: "purgatory-y"}},
	"arch/x86/vdso":              {{"vobjs-y", vdso64}},
	"arch/x86/entry/vdso":        {{"vobjs-y", vdso64}, {"vobjs32-y", []string{"vdso-image-32.o"}}},
	"arch/x86/entry/vdso/vdso64": {{name: "vobjs-y"}},
	"arch/x86/entry/vdso/vdso32": {{name: "vobjs-y"}},
	// The vDSOs of the other label arches, under their directories'
	// conditions; powerpc's 32- and 64-bit lists share one from v6.1 on,
	// and its C objects are named in targets alone.
	"arch/arm64/kernel/vdso":        {{name: "obj-vdso"}},
	"arch/arm64/kernel/vdso32":      {{name: "obj-vdso"}},
	"arch/arm/vdso":                 {{name: "obj-vdso"}},
	"arch/riscv/kernel/vdso":        {{name: "obj-vdso"}},
	"arch/riscv/kernel/compat_vdso": {{name: "obj-compat_vdso"}},
	"arch/loongarch/vdso":           {{name: "obj-vdso"}},
	"arch/powerpc/kernel/vdso":      {{name: "obj-vdso32"}, {name: "obj-vdso64"}, {name: "targets"}},
	"arch/powerpc/kernel/vdso32":    {{name: "obj-vdso32"}},
	"arch/powerpc/kernel/vdso64":    {{name: "obj-vdso64"}},
	"arch/s390/kernel/vdso":         {{name: "obj-vdso"}, {name: "obj-cvdso"}},
	"arch/s390/kernel/vdso32":       {{name: "obj-vdso32"}},
	"arch/s390/kernel/vdso64":       {{name: "obj-vdso64"}, {name: "obj-cvdso64"}},
	// arm64's nVHE hypervisor compiles its list to %.nvhe.o objects and
	// links them into kvm_nvhe.o, which obj-y lists.
	"arch/arm64/kvm/hyp/nvhe": {{"hyp-obj-y", []string{"kvm_nvhe.o"}}},
}

// wrappers are objects that stand for a directory the arch's own rules
// build: arm64's vdso-wrap.S includes vdso/vdso.so, which the arch
// Makefile builds before the kernel, and no list names vdso/. The build
// enters the directory under the object's condition.
var wrappers = map[string]map[string]string{
	"arch/arm64/kernel":   {"vdso-wrap.o": "vdso", "vdso32-wrap.o": "vdso32"},
	"arch/powerpc/kernel": {"vdso32_wrapper.o": "vdso", "vdso64_wrapper.o": "vdso"},
}

// OwnLists returns the lists of directory dir that its own rules link and
// the crawler reads like obj-y.
func OwnLists(dir string) []string {
	var names []string
	for _, l := range ownLists[dir] {
		names = append(names, l.name)
	}
	return names
}

// gate is the condition under which obj-y lists one of the objects of
// gate, false when it lists none.
func gate(ev *evaluator, objs []string) *kcond.Expr {
	ws := list(ev, "obj-y")
	var conds []*kcond.Expr
	for _, o := range objs {
		conds = append(conds, condOf(ws, o))
	}
	return kcond.Or(conds...)
}

// condOf returns the condition of the word text in ws, false when ws
// lacks it.
func condOf(ws []cword, text string) *kcond.Expr {
	for _, w := range ws {
		if w.text == text {
			return w.cond
		}
	}
	return kcond.Const(false)
}

// modes are the conditions under which an object is listed, and under
// which it is compiled into the kernel and into a module.
type modes struct{ cond, builtin, module *kcond.Expr }

// inKernel are the modes of an object of a list the kernel links.
func inKernel(cond *kcond.Expr) modes { return modes{cond, cond, kcond.Const(false)} }

func (m modes) and(c *kcond.Expr) modes {
	return modes{kcond.And(m.cond, c), kcond.And(m.builtin, c), kcond.And(m.module, c)}
}

// twins are the lists Kbuild reads together with their -m twins, which make
// keeps apart: obj-m beside obj-y, lib-m beside lib-y, drivers-m beside
// drivers-y in the top Makefile.
var twins = map[string]bool{"obj-y": true, "lib-y": true, "subdir-y": true, "always-y": true,
	"hostprogs-y": true, "hostprogs-always-y": true, "userprogs-always-y": true,
	"init-y": true, "core-y": true, "drivers-y": true, "net-y": true, "libs-y": true, "virt-y": true}

// list returns the words of a list, with those of its -m twin when Kbuild
// reads both.
func list(ev *evaluator, name string) []cword {
	ws := ev.value(name)
	if twins[name] {
		ws = merge(slices.Concat(ws, ev.value(strings.TrimSuffix(name, "-y")+"-m")))
	}
	return ws
}

// listing records that the Makefile of dir lists a source file, compiled
// with flags.
type listing struct {
	dir, src string
	modes
	flags []flag
	// linked is set for an object of obj-y or obj-m: Kbuild compiles its
	// built-in form only where the directory has need-builtin (see Crawl).
	linked bool
	// object is the object the Makefile lists, without .o, from the top
	// of the tree. For a member of a composite it is the composite. For
	// obj-m += sctp.o, with sctp-y += socket.o, the listing of
	// net/sctp/socket.c has object net/sctp/sctp, so its module is
	// kernel/net/sctp/sctp.ko.
	object string
}

type edge struct {
	parent string
	cond   *kcond.Expr
}

// ErrNoMakefile is the error Crawl returns for a tree without a top-level
// Makefile.
var ErrNoMakefile = errors.New("kbuild: no top-level Makefile")

// Crawl computes the conditions of every source file of the tree in fsys.
func Crawl(fsys fs.FS, opts Options) (*Result, error) {
	if _, err := fs.Stat(fsys, "Makefile"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoMakefile, err)
	}
	arch := opts.Arch
	if _, err := fs.Stat(fsys, "arch/"+arch); err != nil && arch == "x86" {
		if _, err := fs.Stat(fsys, "arch/x86_64"); err == nil {
			arch = "x86_64"
		}
	}
	pre := map[string]string{"srctree": ".", "objtree": ".", "SRCARCH": arch, "ARCH": arch}
	r := &Result{Arch: arch, Files: map[string]*kcond.Expr{}, reached: map[string]bool{},
		makes: map[string]bool{}, compiled: map[string][]compilation{}, subdirFlags: map[string][2][]flag{},
		fsys: fsys, headers: map[string]*kcond.Expr{}, parts: map[string][2]*kcond.Expr{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (d.Name() == "Makefile" || d.Name() == "Kbuild") {
			r.makes[path.Dir(p)] = true
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	var scan sync.WaitGroup
	var scanErr error
	var listed *incListing
	if r.Includes = opts.Includes; r.Includes == nil {
		scan.Go(func() { r.Includes, scanErr = ScanIncludes(fsys) })
		if slices.ContainsFunc(opts.Lookups, func(p string) bool { return path.Ext(p) == ".h" }) {
			// A listing that fails is tried again, and reported, at the
			// first lookup.
			scan.Go(func() { listed, _ = listIncludes(fsys) })
		}
	}
	if arch == "x86" || arch == "x86_64" {
		r.bits = "64"
		if opts.Bits == "32" {
			r.bits = "32"
		}
		pre["BITS"] = r.bits
	}

	// The top-level Makefile, with the arch Makefile it includes, names
	// the directories the build starts from. Its conditions on make
	// variables we do not model (targets, O=, M=) are relaxed away: a
	// directory counts if any value of them lists it.
	top := newEvaluator(fsys, "", pre)
	top.run("Makefile")
	top.frozen = true
	r.Errors = append(r.Errors, top.errors...)
	for _, f := range top.flags("LINUXINCLUDE") {
		if f.kind == includedFile && path.Ext(f.arg) == ".h" {
			r.forced = append(r.forced, flag{includedFile, f.arg, kcond.Relax(f.cond)})
		}
	}
	roots := map[string]*kcond.Expr{}
	for _, name := range rootLists {
		for _, w := range list(top, name) {
			if d, ok := listedDir(w.text); ok && !w.opaque {
				roots[d] = orExpr(roots[d], kcond.Relax(w.cond))
			}
		}
	}
	for _, d := range archDirs[arch] {
		if d = path.Join("arch", arch, d); r.makes[d] {
			roots[d] = kcond.Const(true)
		}
	}

	edges, linkEdges := map[string][]edge{}, map[string][]edge{}
	var listings []listing
	processed := map[string]bool{}
	var queue []string
	for d := range roots {
		queue = append(queue, d)
	}
	// Since v6.1 the root Kbuild lists the top directories, using lists
	// the top-level Makefile exports.
	if _, err := fs.Stat(fsys, "Kbuild"); err == nil {
		ev := newEvaluator(fsys, "", pre)
		ev.vars = top.vars
		ev.run("Kbuild")
		subs, ls := collect(ev, r)
		listings = append(listings, ls...)
		for _, s := range subs {
			edges[s.dir] = append(edges[s.dir], edge{"", kcond.Relax(s.cond)})
			linkEdges[s.dir] = append(linkEdges[s.dir], edge{"", kcond.Relax(s.builtin)})
			queue = append(queue, s.dir)
		}
		processed[""] = true
	}
	slices.Sort(queue)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if processed[d] {
			continue
		}
		processed[d] = true
		r.reached[d] = true
		mk := ""
		for _, name := range []string{"Kbuild", "Makefile"} {
			if _, err := fs.Stat(fsys, path.Join(d, name)); err == nil {
				mk = path.Join(d, name)
				break
			}
		}
		if mk == "" {
			continue
		}
		local := map[string]string{"src": d, "obj": d}
		for k, v := range pre {
			local[k] = v
		}
		ev := newEvaluator(fsys, d, local)
		ev.parent = top
		ev.run(mk)
		subs, ls := collect(ev, r)
		listings = append(listings, ls...)
		for _, s := range subs {
			edges[s.dir] = append(edges[s.dir], edge{d, s.cond})
			linkEdges[s.dir] = append(linkEdges[s.dir], edge{d, s.builtin})
			r.reached[s.dir] = true
			if !processed[s.dir] {
				queue = append(queue, s.dir)
			}
		}
	}

	// The condition under which the build enters each directory, and the
	// one under which it links the directory's obj-y objects: the top
	// directories have need-builtin, and a directory passes it on to those
	// its obj-y lists (scripts/Makefile.build drops the directories of obj-y
	// without it). A directory entered through obj-m or subdir-y alone
	// compiles only its modules, lib-y and always-y.
	dirs := dirConditions(roots, edges, processed[""])
	links := dirConditions(roots, linkEdges, processed[""])
	memo, visiting := map[string][2][]flag{}, map[string]bool{}
	for _, l := range listings {
		dc, ok := dirs[l.dir]
		if l.dir == "" {
			dc, ok = kcond.Const(true), true
		}
		if !ok {
			continue
		}
		db := dc
		if l.linked && l.dir != "" {
			if db = links[l.dir]; db == nil {
				db = kcond.Const(false)
			}
		}
		// A linked object needs the directory linked, unless it is a module.
		c := kcond.And(dc, l.cond)
		if l.linked && db.String() != dc.String() {
			if l.module.IsConst(false) {
				c = kcond.And(db, l.cond)
			} else {
				c = kcond.And(c, kcond.Or(db, l.module))
			}
		}
		builtin, module := kcond.And(db, l.builtin), kcond.And(dc, l.module)
		r.Files[l.src] = orExpr(r.Files[l.src], c)
		fl := r.inherited(l.dir, edges, memo, visiting)
		sub := fl[0]
		if path.Ext(l.src) == ".S" {
			sub = fl[1]
		}
		r.compiled[l.src] = append(r.compiled[l.src], compilation{cond: c, builtin: builtin, module: module,
			object: l.object, flags: slices.Concat(l.flags, sub)})
	}
	if scan.Wait(); scanErr != nil {
		return nil, scanErr
	}
	if listed != nil {
		r.Includes.listed = listed
	}
	r.include(fsys)
	r.subdirFlags = nil
	return r, nil
}

// inherited returns the subdir-ccflags-y and subdir-asflags-y flags that
// apply in directory d: its own and those of every directory the build
// enters it from.
func (r *Result) inherited(d string, edges map[string][]edge, memo map[string][2][]flag, visiting map[string]bool) [2][]flag {
	if fl, ok := memo[d]; ok || visiting[d] {
		return fl
	}
	visiting[d] = true
	fl := r.subdirFlags[d]
	for _, e := range edges[d] {
		p := r.inherited(e.parent, edges, memo, visiting)
		fl = [2][]flag{slices.Concat(fl[0], p[0]), slices.Concat(fl[1], p[1])}
	}
	delete(visiting, d)
	memo[d] = fl
	return fl
}

func orExpr(a, b *kcond.Expr) *kcond.Expr {
	if a == nil {
		return b
	}
	return kcond.Or(a, b)
}

// listedDir maps a top-level list entry (dir/, dir/built-in.o, dir/lib.a)
// to its directory.
func listedDir(w string) (string, bool) {
	for _, suf := range []string{"/built-in.o", "/built-in.a", "/lib.a", "/"} {
		if d, ok := strings.CutSuffix(w, suf); ok && d != "" {
			return cleanPath(d), true
		}
	}
	return "", false
}

// dirConditions propagates conditions from the roots down the edges, from
// a directory to those its Makefile lists or from a source to the files it
// #includes. A directory listed by several Makefiles gets the OR. A file is
// computed once its parents are, so that each is computed once; the graph
// can have cycles through ../, whose files are then iterated to a fixed
// point, a file changing 32 times stopping, which bounds a cycle.
func dirConditions(roots map[string]*kcond.Expr, edges map[string][]edge, rootKbuild bool) map[string]*kcond.Expr {
	conds := map[string]*kcond.Expr{}
	for d, c := range roots {
		conds[d] = c
	}
	if rootKbuild {
		conds[""] = kcond.Const(true)
	}
	files := slices.Sorted(maps.Keys(edges))
	children := map[string][]string{} // by parent
	pending := map[string]int{}       // parents still to compute
	for _, d := range files {
		for _, e := range edges[d] {
			children[e.parent] = append(children[e.parent], d)
			if edges[e.parent] != nil {
				pending[d]++
			}
		}
	}
	// compute reads d's condition off its parents' and reports a change.
	compute := func(d string) bool {
		var terms []*kcond.Expr
		if c, ok := roots[d]; ok {
			terms = append(terms, c)
		}
		for _, e := range edges[d] {
			if pc, ok := conds[e.parent]; ok {
				terms = append(terms, kcond.And(pc, e.cond))
			}
		}
		if len(terms) == 0 {
			return false
		}
		c := kcond.Or(terms...)
		if old, ok := conds[d]; ok && old.String() == c.String() {
			return false
		}
		conds[d] = c
		return true
	}
	var queue []string
	for _, d := range files {
		if pending[d] == 0 {
			queue = append(queue, d)
		}
	}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		compute(d)
		for _, ch := range children[d] {
			if pending[ch]--; pending[ch] == 0 {
				queue = append(queue, ch)
			}
		}
	}
	// The rest are in or below a cycle.
	queued := map[string]bool{}
	for _, d := range files {
		if pending[d] > 0 {
			queue = append(queue, d)
			queued[d] = true
		}
	}
	changes := map[string]int{}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		delete(queued, d)
		if !compute(d) {
			continue
		}
		if changes[d]++; changes[d] < 32 {
			for _, ch := range children[d] {
				if !queued[ch] {
					queued[ch] = true
					queue = append(queue, ch)
				}
			}
		}
	}
	delete(conds, "")
	return conds
}

type subdir struct {
	dir  string
	cond *kcond.Expr
	// builtin is the condition under which obj-y lists the directory,
	// which gives it need-builtin.
	builtin *kcond.Expr
}

// maxComposite bounds the nesting of composite objects.
const maxComposite = 10

// collect reads the objects and subdirectories a Makefile lists once it
// has been evaluated.
func collect(ev *evaluator, r *Result) ([]subdir, []listing) {
	ev.frozen = true
	var subs []subdir
	var ls []listing
	var words, objs []cword // objs: obj-y and obj-m, which link
	// An object is compiled into a module where obj-m lists it and obj-y
	// does not, as Kbuild filters obj-m by obj-y.
	ys, ms := ev.value("obj-y"), ev.value("obj-m")
	own := OwnLists(ev.dir)
	gates := map[string]*kcond.Expr{}
	for _, l := range ownLists[ev.dir] {
		if l.gate != nil {
			gates[l.name] = gate(ev, l.gate)
		}
	}
	// extra-y and always-y name objects built beside the directory's
	// built-in.a, such as arch/x86/kernel's head code and vmlinux.lds.
	for _, name := range slices.Concat([]string{"obj-y", "lib-y", "subdir-y", "extra-y", "always-y"}, own, programs) {
		isOwn, isProg := slices.Contains(own, name), slices.Contains(programs, name)
		g, gated := gates[name]
		if gated && g.IsConst(false) {
			continue
		}
		for _, w := range list(ev, name) {
			if w.opaque {
				ev.note(w.text, name)
				continue
			}
			if name == "subdir-y" && !strings.HasSuffix(w.text, "/") {
				w.text += "/"
			}
			if isOwn {
				w.text = strings.TrimPrefix(w.text, ev.dir+"/")
			}
			if gated {
				w.cond = kcond.And(w.cond, g)
			}
			if isProg {
				w.text += ".o"
			}
			if name == "obj-y" {
				objs = append(objs, w)
			} else {
				words = append(words, w)
			}
		}
	}
	add := func(w cword, linked bool) {
		switch {
		case strings.HasSuffix(w.text, "/"):
			d := cleanPath(path.Join(ev.dir, w.text))
			if d != "." && !strings.HasPrefix(d, "../") {
				subs = append(subs, subdir{d, w.cond, condOf(ys, w.text)})
			}
		case strings.HasSuffix(w.text, ".o"):
			if d, ok := wrappers[ev.dir][w.text]; ok {
				subs = append(subs, subdir{path.Join(ev.dir, d), w.cond, condOf(ys, w.text)})
			}
			k := inKernel(w.cond)
			if m := condOf(ms, w.text); !m.IsConst(false) {
				m = kcond.And(m, kcond.Not(condOf(ys, w.text)))
				k.builtin, k.module = kcond.And(w.cond, kcond.Not(m)), m
			}
			// w.text is the listed object. resolveObject expands a composite
			// into its members, so the object must be noted here, before
			// the expansion forgets which composite each member belongs to.
			object := cleanPath(path.Join(ev.dir, strings.TrimSuffix(w.text, ".o")))
			for _, l := range resolveObject(ev, w.text, k, map[string]bool{w.text: true}) {
				l.linked, l.object = linked, object
				ls = append(ls, l)
			}
		case strings.HasSuffix(w.text, ".lds"):
			ls = append(ls, leaf(ev, w.text, inKernel(w.cond))...) // X.lds from X.lds.S
		}
	}
	for _, w := range merge(words) {
		add(w, false)
	}
	for _, w := range merge(objs) {
		add(w, true)
	}
	// .s targets are compiled from C for the offsets headers they
	// generate, as the top-level Kbuild's kernel/bounds.s.
	for _, w := range ev.value("targets") {
		if stem, ok := strings.CutSuffix(w.text, ".s"); ok && !w.opaque {
			ls = append(ls, leaf(ev, stem, inKernel(w.cond))...)
		}
	}
	if c, as := ev.flags("subdir-ccflags-y"), ev.flags("subdir-asflags-y"); c != nil || as != nil {
		r.subdirFlags[ev.dir] = [2][]flag{c, as}
	}
	r.Errors = append(r.Errors, ev.errors...)
	return subs, ls
}

// objFlags returns the -I, -D and -include flags the Makefile gives the object obj
// compiled from a source with extension ext: those of the directory and
// those of the object, named as compiled (Kbuild's target-stem), which for
// a renamed object such as foo.stub.o may be foo.o.
func objFlags(ev *evaluator, obj, ext string) []flag {
	vars, prefix := []string{"ccflags-y", "EXTRA_CFLAGS"}, "CFLAGS_"
	switch ext {
	case ".c":
	case ".S":
		vars, prefix = []string{"asflags-y", "EXTRA_AFLAGS"}, "AFLAGS_"
	default:
		return nil
	}
	stem := strings.TrimSuffix(obj, ".o")
	for _, o := range []string{stem, strings.TrimSuffix(stem, path.Ext(stem))} {
		vars = append(vars, prefix+o+".o")
	}
	var fl []flag
	for _, v := range slices.Compact(vars) {
		fl = append(fl, ev.flags(v)...)
	}
	return fl
}

// resolveObject expands a composite object into its members, which share
// its modes, or maps a simple object to its source file. As Kbuild links
// them, the members of foo-objs and foo-y belong to the composite either
// way, those of foo-m only when it is a module.
func resolveObject(ev *evaluator, obj string, k modes, visited map[string]bool) []listing {
	stem := strings.TrimSuffix(obj, ".o")
	builtin, modular := merge(slices.Concat(ev.value(stem+"-objs"), ev.value(stem+"-y"))), ev.value(stem+"-m")
	members := merge(slices.Concat(builtin, modular))
	if len(members) > 0 && !(len(members) == 1 && members[0].text == obj) && len(visited) <= maxComposite {
		var out []listing
		for _, m := range members {
			if m.opaque {
				ev.note(m.text, stem+"-y")
				continue
			}
			if !strings.HasSuffix(m.text, ".o") {
				continue
			}
			c := k.and(condOf(builtin, m.text))
			if mod := kcond.And(k.module, condOf(modular, m.text)); !mod.IsConst(false) {
				c = modes{kcond.Or(c.cond, mod), c.builtin, kcond.Or(c.module, mod)}
			}
			if m.text == obj {
				out = append(out, leaf(ev, obj, c)...)
				continue
			}
			if visited[m.text] {
				continue
			}
			visited[m.text] = true
			out = append(out, resolveObject(ev, m.text, c, visited)...)
			delete(visited, m.text)
		}
		return out
	}
	return leaf(ev, obj, k)
}

// sourceExts are the extensions of the sources objects are compiled from,
// in the order a stem's source is looked for.
var sourceExts = []string{".c", ".S", ".rs", ".s"}

// maxObjectRules bounds the rules followed from one object to another.
const maxObjectRules = 4

// leaf maps an object to the source it is compiled from. A renamed object
// such as foo.stub.o or foo.pi.o, which a rule makes of foo.o, comes from
// foo's source when foo.stub itself has none. An object without a source
// of its own name comes from the one a rule of the Makefile names, as xe
// compiles i915's display code, or from the object the rule makes it of,
// as lkdtm objcopies rodata_objcopy.o of rodata.o; make would prefer the
// rule even where the object's own source exists, which no tree has. Make
// takes the first rule that applies, so one under a condition leaves the
// later ones where it does not hold.
func leaf(ev *evaluator, obj string, k modes) []listing { return leafAt(ev, obj, k, 0) }

// leafAt is leaf, depth rules away from the listed object.
func leafAt(ev *evaluator, obj string, k modes, depth int) []listing {
	stem := cleanPath(path.Join(ev.dir, strings.TrimSuffix(obj, ".o")))
	stems := slices.Compact([]string{stem, strings.TrimSuffix(stem, path.Ext(stem))})
	for _, s := range stems {
		for _, ext := range sourceExts {
			if _, err := fs.Stat(ev.fsys, s+ext); err == nil {
				return []listing{{dir: ev.dir, src: s + ext, modes: k, flags: objFlags(ev, obj, ext)}}
			}
		}
	}
	if !strings.HasSuffix(obj, ".o") {
		return nil
	}
	var out []listing
	taken := kcond.Const(false) // where an earlier rule applies
	for _, s := range stems {
		for _, ru := range ev.rules {
			if !matches(ru.target, s+".o") {
				continue
			}
			src := patsubst(ru.target, ru.source, s+".o")
			c := kcond.And(ru.cond, kcond.Not(taken))
			if c.IsConst(false) {
				continue
			}
			var more []listing
			if path.Ext(src) == ".o" {
				if depth < maxObjectRules {
					more = leafAt(ev, strings.TrimPrefix(src, ev.dir+"/"), k.and(c), depth+1)
				}
			} else if _, err := fs.Stat(ev.fsys, src); err == nil {
				more = []listing{{dir: ev.dir, src: src, modes: k.and(c), flags: objFlags(ev, obj, path.Ext(src))}}
			}
			if len(more) == 0 {
				continue
			}
			out = append(out, more...)
			if taken = kcond.Or(taken, ru.cond); taken.IsConst(true) {
				return out
			}
		}
	}
	return out
}
