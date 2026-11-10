// Package builds reads a kernel tree as each of its architecture builds
// does: the x86-64 and i386 builds of x86 and the builds of the other
// label arches. It gives a changed file its Kbuild condition and region
// in a build, tells which arches may or always build it, combines the
// files of a change into one condition and summarizes the arches.
package builds

import (
	"errors"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/kbuild"
	"github.com/corefense-security/kcond/kconfig"
)

// LabelArches are the architectures labels name, in display order; x86
// stands for both x86-64 and i386.
var LabelArches = []string{"x86", "arm64", "arm", "powerpc", "s390", "riscv", "loongarch"}

// Primary is the architecture the main condition is computed for.
const Primary = "x86"

// X86_64Build is the build whose condition the main condition holds.
const X86_64Build = "x86_64"

// BuildArch names a build as LabelArches do: x86 for both x86 builds.
func BuildArch(build string) string {
	if build == X86_64Build || build == "i386" {
		return "x86"
	}
	return build
}

// ConfigBuilds are the architecture builds conditions are computed for:
// x86-64, i386 and the other LabelArches.
var ConfigBuilds = slices.Concat([]string{X86_64Build, "i386"}, LabelArches[1:])

// ArchLabels are the labels Summarize gives other than an architecture
// name: generic code builds on every label arch of its release but s390,
// several on more than one, other only on architectures outside
// LabelArches, none on none.
var ArchLabels = []string{"generic", "several", "other", "none"}

// OptionalArch is the label arch generic code need not build on: s390 has
// no wireless, Bluetooth or sound, so leaving it out does not make a change
// arch-specific.
const OptionalArch = "s390"

// KconfigOptions are the options every Kconfig analysis uses. COMPILE_TEST
// builds drivers on architectures they cannot run on, and production
// kernels never enable it, so it is off.
func KconfigOptions() kconfig.Options { return kconfig.Options{Off: []string{"COMPILE_TEST"}} }

// ArchVerdict tells whether a changed file may build on an architecture.
type ArchVerdict uint8

const (
	ArchNo ArchVerdict = iota
	ArchYes
	ArchMaybe // its condition there is unknown
)

// Build is one architecture's build of a tree; x86 has an x86-64 and an
// i386 one.
type Build struct {
	Arch   string // a label arch
	Name   string // the build's name in ConfigBuilds
	X86_64 bool   // the x86-64 build, which decides whether x86 always builds a file
	Kbuild *kbuild.Result
	Values *kconfig.Values // nil when the Kconfig could not be read
	// Defined are the CONFIG_ symbols some Kconfig file of the whole tree
	// defines (see Defined), which tells a symbol of another arch from one
	// no Kconfig has yet; nil when they could not be read.
	Defined map[string]bool
	Err     error // why Kbuild, Values or Defined is nil
}

// SrcArch returns the arch/ directory of a label arch in the tree,
// arch/x86_64 for x86 before v2.6.24, or "" when the tree has none.
func SrcArch(fsys fs.FS, arch string) string {
	dirs := []string{arch}
	if arch == "x86" {
		dirs = append(dirs, "x86_64")
	}
	for _, d := range dirs {
		if _, err := fs.Stat(fsys, "arch/"+d+"/Kconfig"); err == nil {
			return d
		}
	}
	return ""
}

// KconfigEnv is the environment for reading the Kconfig of an arch/
// directory; x86 is read as x86-64.
func KconfigEnv(dir string) kconfig.Env {
	arch := dir
	if dir == "x86" {
		arch = "x86_64"
	}
	return kconfig.Env{"SRCARCH": dir, "ARCH": arch}
}

// buildSpec is how one build reads a tree.
type buildSpec struct {
	arch, name string
	opts       kbuild.Options
	env        kconfig.Env
}

// buildSpecs lists the builds of the label arches the tree has: x86-64
// first, then i386, then the other arches in LabelArches order.
func buildSpecs(fsys fs.FS) []buildSpec {
	var specs []buildSpec
	for _, arch := range LabelArches {
		dir := SrcArch(fsys, arch)
		if dir == "" {
			continue
		}
		name := arch
		if arch == "x86" {
			name = X86_64Build
		}
		specs = append(specs, buildSpec{arch, name, kbuild.Options{Arch: dir}, KconfigEnv(dir)})
		if arch != "x86" {
			continue
		}
		if _, err := fs.Stat(fsys, "arch/i386/Kconfig"); err == nil {
			specs = append(specs, buildSpec{arch, "i386", kbuild.Options{Arch: "i386"}, kconfig.Env{"SRCARCH": "i386", "ARCH": "i386"}})
		} else {
			specs = append(specs, buildSpec{arch, "i386", kbuild.Options{Arch: dir, Bits: "32"}, kconfig.Env{"SRCARCH": dir, "ARCH": "i386"}})
		}
	}
	return specs
}

// specOf returns how build reads the tree; ok is false when the tree has
// no such architecture.
func specOf(fsys fs.FS, build string) (sp buildSpec, ok bool) {
	for _, sp := range buildSpecs(fsys) {
		if sp.name == build {
			return sp, true
		}
	}
	return buildSpec{}, false
}

// values analyzes the Kconfig the build reads.
func (sp buildSpec) values(fsys fs.FS) (*kconfig.Values, error) {
	tr, err := kconfig.Parse(fsys, sp.env)
	if err != nil {
		return nil, err
	}
	return kconfig.Analyze(tr, KconfigOptions()), nil
}

// Each calls f with each build of the label arches the tree has, one at
// a time so that only one crawl is held: the x86-64 build first, reusing
// x86 when it is not nil, then i386, then the other arches in LabelArches
// order. A build whose crawl or Kconfig fails is passed with that field
// nil and Err saying why, so its files stay unknown rather than its arch
// absent. The crawls
// share one scan of the tree's #include directives, x86's when given.
// lookups are the files f will look up (see kbuild.Options).
func Each(fsys fs.FS, x86 *kbuild.Result, lookups []string, f func(Build) error) error {
	defined, err := Defined(fsys)
	if err != nil {
		return err
	}
	var inc *kbuild.Includes
	for _, sp := range buildSpecs(fsys) {
		b := Build{Arch: sp.arch, Name: sp.name, X86_64: sp.name == X86_64Build, Defined: defined}
		sp.opts.Includes, sp.opts.Lookups = inc, lookups
		var crawlErr, kconfigErr error
		if b.X86_64 && x86 != nil {
			b.Kbuild, inc = x86, x86.Includes
		} else if res, err := kbuild.Crawl(fsys, sp.opts); err == nil {
			b.Kbuild, inc = res, res.Includes
		} else {
			crawlErr = err
		}
		b.Values, kconfigErr = sp.values(fsys)
		b.Err = errors.Join(crawlErr, kconfigErr)
		if err := f(b); err != nil {
			return err
		}
	}
	return nil
}

// Named returns the build named name (one of ConfigBuilds) of the tree,
// its crawl and its Kconfig analysis run at once. ok is false when the
// tree has no such architecture; a crawl or Kconfig that fails leaves its
// field nil and Err saying why. lookups are the files the caller will look
// up (see kbuild.Options).
func Named(fsys fs.FS, name string, lookups []string) (b Build, ok bool) {
	sp, ok := specOf(fsys, name)
	if !ok {
		return Build{}, false
	}
	sp.opts.Lookups = lookups
	b = Build{Arch: sp.arch, Name: name, X86_64: name == X86_64Build}
	var analysis sync.WaitGroup
	var kconfigErr, definedErr error
	analysis.Go(func() { b.Values, kconfigErr = sp.values(fsys) })
	analysis.Go(func() { b.Defined, definedErr = Defined(fsys) })
	res, crawlErr := kbuild.Crawl(fsys, sp.opts)
	if crawlErr == nil {
		b.Kbuild = res
	}
	analysis.Wait()
	b.Err = errors.Join(crawlErr, kconfigErr, definedErr)
	return b, true
}

var configDef = regexp.MustCompile(`(?m)^\s*(?:menu)?config\s+([A-Za-z0-9_]+)`)

// Defined returns the CONFIG_ symbols some Kconfig file of the tree
// defines, for any architecture.
func Defined(fsys fs.FS) (map[string]bool, error) {
	defined := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(d.Name(), "Kconfig") {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		for _, m := range configDef.FindAllSubmatch(data, -1) {
			defined["CONFIG_"+string(m[1])] = true
		}
		return nil
	})
	return defined, err
}

// srcArchDirs are the directories whose Makefiles add -I$(src)/$(SRCARCH),
// keeping a directory of assembly and glue code per architecture.
var srcArchDirs = []string{"lib/crc/", "lib/crypto/", "lib/raid/raid6/", "lib/raid/xor/"}

// archNames are the directories of arch/.
var archNames = map[string]bool{"alpha": true, "arc": true, "arm": true, "arm64": true, "csky": true, "hexagon": true,
	"loongarch": true, "m68k": true, "microblaze": true, "mips": true, "nios2": true, "openrisc": true, "parisc": true,
	"powerpc": true, "riscv": true, "s390": true, "sh": true, "sparc": true, "um": true, "x86": true, "xtensa": true}

// PathArch is the architecture of a path under arch/, with the old i386,
// x86_64, ppc and sparc64 directories folded into their successors, or
// under <dir>/<arch>/ for one of srcArchDirs; "" for other paths.
func PathArch(p string) string {
	for _, dir := range srcArchDirs {
		if rest, ok := strings.CutPrefix(p, dir); ok {
			if a, _, _ := strings.Cut(rest, "/"); archNames[a] {
				return a
			}
		}
	}
	rest, ok := strings.CutPrefix(p, "arch/")
	if !ok {
		return ""
	}
	a, sub, _ := strings.Cut(rest, "/")
	switch a {
	case "x86":
		if strings.HasPrefix(sub, "um/") {
			return "um" // user-mode Linux on an x86 host
		}
	case "i386", "x86_64":
		return "x86"
	case "ppc", "ppc64":
		return "powerpc"
	case "sparc64":
		return "sparc"
	}
	return a
}

// free makes the CONFIG_ symbols of e that defined lacks opaque; nil
// defined frees nothing.
func free(e *kcond.Expr, defined map[string]bool) *kcond.Expr {
	if defined == nil {
		return e
	}
	switch e.Op {
	case kcond.OpVar:
		if kcond.IsSymbol(e.Name) && !defined[e.Name] {
			return kcond.Var("undefined:"+e.Name, kcond.Enabled)
		}
	case kcond.OpNot:
		return kcond.Not(free(e.Args[0], defined))
	case kcond.OpAnd, kcond.OpOr:
		args := make([]*kcond.Expr, len(e.Args))
		for i, a := range e.Args {
			args[i] = free(a, defined)
		}
		if e.Op == kcond.OpAnd {
			return kcond.And(args...)
		}
		return kcond.Or(args...)
	}
	return e
}

// BuildCond is a changed file's condition in build b: a file under another
// architecture's directory (see PathArch) is not built, a source gets what
// b's Makefiles say, a header the condition of the files that include it
// when they are all known (see kbuild.Result.Lookup) and the status header
// otherwise, and either is unlisted when b's crawl failed. The region is
// as b reads it, and both are written plainly (see Build.Plain); a file
// whose condition is then false, as one listed under another arch's
// symbol, is not built.
func BuildCond(path string, header bool, region *kcond.Expr, b Build) FileCond {
	fc := FileCond{Header: header, Region: b.Plain(b.Region(path, region))}
	switch pa := PathArch(path); {
	case pa != "" && pa != b.Arch:
		fc.Status = StatusNotBuilt
	case b.Kbuild == nil:
		fc.Status = StatusUnlisted
	default:
		fc.Status, fc.Kbuild = KbuildStatus(b.Kbuild, path)
		if fc.Kbuild = b.Plain(fc.Kbuild); fc.Kbuild != nil && fc.Kbuild.IsConst(false) {
			fc.Status, fc.Kbuild = StatusNotBuilt, nil
		}
	}
	if header && fc.Status == StatusUnlisted {
		fc.Status = StatusHeader
	}
	return fc
}

// term is the condition under which b builds the changed lines of a file,
// or nil with what b can tell without one: ArchNo when it does not build
// the file, ArchMaybe when the file's condition there is unknown.
func term(path string, header bool, region *kcond.Expr, b Build) (*kcond.Expr, ArchVerdict) {
	pa := PathArch(path)
	if pa != "" && pa != b.Arch {
		return nil, ArchNo
	}
	if b.Values == nil || (b.Kbuild == nil && !header) {
		return nil, ArchMaybe
	}
	region = b.Region(path, region)
	var e *kcond.Expr
	st := kbuild.Unlisted
	if b.Kbuild != nil {
		e, st = b.Kbuild.Lookup(path)
	}
	// A header whose includers are not known is judged by its region.
	if header && st != kbuild.Built {
		switch {
		case region.IsConst(false):
			return nil, ArchNo
		case len(region.Symbols()) == 0:
			return nil, ArchMaybe
		}
		return region, ArchYes
	}
	switch st {
	case kbuild.Built:
		return kcond.And(e, region), ArchYes
	case kbuild.NotBuilt:
		if pa == b.Arch {
			// Built by rules the crawl does not follow, or only for
			// the other word size.
			return nil, ArchMaybe
		}
		return nil, ArchNo
	}
	return nil, ArchMaybe
}

// FileArch tells whether a changed file may build in b: its Kbuild
// condition there, ANDed with the region of its changed lines, must be
// possible under b's Kconfig. Symbols not in b.Defined become opaque (nil
// frees nothing), so one no Kconfig file defines yet, often added by the
// fix itself, neither rules the file in nor out.
func FileArch(path string, header bool, region *kcond.Expr, b Build) ArchVerdict {
	t, v := term(path, header, region, b)
	if t == nil {
		return v
	}
	if b.Values.Possible(free(t, b.Defined)) {
		return ArchYes
	}
	return ArchNo
}

// AlwaysBuilt reports whether a changed file is built in every
// configuration of b: a source listed under a condition that always holds,
// or a header whose changed lines are under a CONFIG_ condition that does.
// For x86 only the x86-64 build decides; the i386 one never does.
func AlwaysBuilt(path string, header bool, region *kcond.Expr, b Build) bool {
	if b.Arch == "x86" && !b.X86_64 {
		return false
	}
	t, _ := term(path, header, region, b)
	return t != nil && b.Values.Always(free(t, b.Defined))
}

// FileArches gathers what the builds of a file's revision say about it.
type FileArches struct {
	Path   string
	Header bool
	// Verdicts are by label arch; x86 merges its x86-64 and i386 builds.
	Verdicts map[string]ArchVerdict
	Always   []string // the label arches every configuration of which builds the file
	Present  []string // the label arches the revision has; empty until a build ran
}

// Add records what build b says about the file, whose changed lines are
// under region.
func (f *FileArches) Add(b Build, region *kcond.Expr) {
	if f.Verdicts == nil {
		f.Verdicts = map[string]ArchVerdict{}
	}
	v := FileArch(f.Path, f.Header, region, b)
	if old, ok := f.Verdicts[b.Arch]; ok && (old == ArchYes || (old == ArchMaybe && v == ArchNo)) {
		v = old
	}
	f.Verdicts[b.Arch] = v
	if AlwaysBuilt(f.Path, f.Header, region, b) {
		f.Always = append(f.Always, b.Arch)
	}
	if !slices.Contains(f.Present, b.Arch) {
		f.Present = append(f.Present, b.Arch)
	}
}

// Lists returns the label arches the file may build on, known or not, and
// those of them where its condition is unknown.
func (f *FileArches) Lists() (arches, unknown []string) {
	arches, unknown = []string{}, []string{}
	for _, a := range LabelArches {
		switch f.Verdicts[a] {
		case ArchMaybe:
			unknown = append(unknown, a)
			fallthrough
		case ArchYes:
			arches = append(arches, a)
		}
	}
	return arches, unknown
}

// ArchSummary is the architecture data of a change.
type ArchSummary struct {
	Arches []string // label arches that may build the changed code
	// Unknown are the Arches only files with an unknown condition give.
	Unknown []string
	// Uncertain is set when Unknown is not empty or a counted file was
	// never found at any revision.
	Uncertain bool
	// Always are the Arches every configuration of which builds the code.
	Always []string
	Label  string
}

// Summarize combines the files of a change the way Combine does: sources
// count, headers only when no source changed. The label covers the label
// arches present at the files' revisions: generic when every one but
// OptionalArch may build the code, the arch's name when only one does,
// several otherwise; other when every counted path is under an
// architecture outside the label set, none when no label arch builds it,
// and "" when no file was analysed.
func Summarize(files []FileArches) ArchSummary {
	s := ArchSummary{Arches: []string{}, Unknown: []string{}, Always: []string{}}
	sources := slices.ContainsFunc(files, func(f FileArches) bool { return !f.Header })
	yes, maybe, present, always := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	found, labelPath := false, false // labelPath: a counted path outside arch/ or under a label arch
	for _, f := range files {
		for _, a := range f.Present {
			present[a] = true
		}
		if sources && f.Header {
			continue
		}
		pa := PathArch(f.Path)
		labelPath = labelPath || pa == "" || slices.Contains(LabelArches, pa)
		found = found || len(f.Present) > 0
		if len(f.Present) == 0 {
			s.Uncertain = true
			continue
		}
		for a, v := range f.Verdicts {
			switch v {
			case ArchYes:
				yes[a] = true
			case ArchMaybe:
				maybe[a] = true
			}
		}
		for _, a := range f.Always {
			always[a] = true
		}
	}
	var in []string
	for _, a := range LabelArches {
		if !yes[a] && !maybe[a] {
			continue
		}
		s.Arches = append(s.Arches, a)
		if !yes[a] {
			s.Unknown = append(s.Unknown, a)
		}
		if always[a] {
			s.Always = append(s.Always, a)
		}
		if present[a] {
			in = append(in, a)
		}
	}
	s.Uncertain = s.Uncertain || len(s.Unknown) > 0
	switch {
	case !found:
	case len(in) == 0 && !labelPath:
		s.Label = "other"
	case len(in) == 0:
		s.Label = "none"
	case !slices.ContainsFunc(LabelArches, func(a string) bool { return present[a] && a != OptionalArch && !yes[a] && !maybe[a] }):
		s.Label = "generic"
	case len(in) == 1:
		s.Label = in[0]
	default:
		s.Label = "several"
	}
	return s
}
