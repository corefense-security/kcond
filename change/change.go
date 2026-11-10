// Package change reads what a commit changes in a kernel tree: the
// kernel files its diff touches, with the #if and IS_ENABLED() region of
// the changed lines, and the verdict of a condition for a .config.
package change

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/kbuild"
	"github.com/corefense-security/kcond/unidiff"
)

// Blobs reads file contents by rev:path; gitfs.CatFile implements it.
type Blobs interface {
	Get(spec string) ([]byte, bool, error)
}

// FileChange is a kernel source or header a commit changes.
type FileChange struct {
	// Path is the path before the commit, or after it when the commit
	// creates the file.
	Path   string
	Header bool
	// Region is the OR of the conditions of the changed code lines:
	// deleted lines in the old file, added lines in the new one. It is true
	// when a file cannot be analyzed.
	Region *kcond.Expr
	// Functions are the hunk headers git shows, normally the functions.
	Functions []string
	// Code is false when no hunk changes code: every changed line is a
	// comment or blank, or the hunk only moves comments and blanks around
	// code it keeps.
	Code bool
}

// Kernel reports whether p is a C, assembly or Rust file of the kernel
// proper (not documentation, tools or scripts), and whether it is a header.
func Kernel(p string) (ok, header bool) {
	for _, pre := range []string{"Documentation/", "tools/", "scripts/", "LICENSES/"} {
		if strings.HasPrefix(p, pre) {
			return false, false
		}
	}
	switch path.Ext(p) {
	case ".c", ".S", ".s", ".rs":
		return true, false
	case ".h":
		return true, true
	}
	return false, false
}

// OutsideBuild reports whether building the kernel never reads p:
// documentation, licenses, selftests, perf, and the top-level files that
// describe the tree (MAINTAINERS, CREDITS, COPYING, README and the
// dotfiles). Other tools are left in, as the build runs some (objtool,
// resolve_btfids, bootconfig), and so is any Kconfig file, as the top one
// sources Documentation/Kconfig.
func OutsideBuild(p string) bool {
	if strings.HasPrefix(path.Base(p), "Kconfig") {
		return false
	}
	if !strings.Contains(p, "/") {
		switch p {
		case "MAINTAINERS", "CREDITS", "COPYING", "README":
			return true
		}
		return strings.HasPrefix(p, ".")
	}
	for _, pre := range []string{"Documentation/", "LICENSES/", "tools/testing/", "tools/perf/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Changes lists the kernel files the commit hash changes, given its
// diff, with the condition of the changed lines. Images are read from b as
// hash^:path and hash:path, and as hash^2:path and on for the further
// parents of a merge's combined diff.
func Changes(b Blobs, hash, diff string) []FileChange {
	var out []FileChange
	for _, fd := range unidiff.Files(diff) {
		p := fd.OldPath
		if p == "" {
			p = fd.NewPath
		}
		ok, header := Kernel(p)
		if !ok || len(fd.Hunks) == 0 {
			continue
		}
		var add int
		for _, h := range fd.Hunks {
			add += len(h.Added)
		}
		olds := map[int]*kcond.Source{} // by parent
		var newSrc *kcond.Source
		var bad bool
		image := func(rev, file string) *kcond.Source {
			data, found, err := b.Get(rev + ":" + file)
			if err != nil || !found {
				bad = true
				return nil
			}
			src, err := kcond.Analyze(data, kbuild.CodeOf(file))
			if err != nil {
				bad = true
				return nil
			}
			return src
		}
		for _, h := range fd.Hunks {
			if _, read := olds[h.Parent]; !read && len(h.Deleted) > 0 && fd.OldPath != "" {
				rev := hash + "^"
				if h.Parent > 0 {
					rev += strconv.Itoa(h.Parent + 1)
				}
				olds[h.Parent] = image(rev, fd.OldPath)
			}
		}
		if add > 0 && fd.NewPath != "" {
			newSrc = image(hash, fd.NewPath)
		}
		// Path and Functions are cloned: as substrings they would keep the
		// whole diff alive for as long as the change.
		fc := FileChange{Path: strings.Clone(p), Header: header, Region: kcond.Const(false)}
		seen := map[string]bool{}
		for _, h := range fd.Hunks {
			if h.Func != "" && !seen[h.Func] {
				seen[h.Func] = true
				fc.Functions = append(fc.Functions, strings.Clone(h.Func))
			}
		}
		if bad {
			fc.Region, fc.Code = kcond.Const(true), true
			out = append(out, fc)
			continue
		}
		var terms []*kcond.Expr
		lines := func(src *kcond.Source, nums []int) {
			for _, n := range nums {
				if src != nil && n >= 1 && n <= len(src.Text) && src.Text[n-1] != "" {
					terms = append(terms, src.Cond(n-1))
				}
			}
		}
		// code lists the code of the n lines of src from line start, the
		// context lines of a hunk included.
		code := func(src *kcond.Source, start, n int) (texts []string) {
			for i := max(start, 1); src != nil && i < start+n && i <= len(src.Text); i++ {
				if src.Text[i-1] != "" {
					texts = append(texts, src.Text[i-1])
				}
			}
			return texts
		}
		for _, h := range fd.Hunks {
			// A hunk whose code reads the same before and after only moves
			// comments or blank lines.
			oldSrc := olds[h.Parent]
			if slices.Equal(code(oldSrc, h.OldStart, h.OldLines), code(newSrc, h.NewStart, h.NewLines)) {
				continue
			}
			lines(oldSrc, h.Deleted)
			lines(newSrc, h.Added)
		}
		fc.Code = len(terms) > 0
		fc.Region = kcond.Or(terms...)
		out = append(out, fc)
	}
	return out
}

// Short drops from every AND of e the plain CONFIG_X terms that another
// enabled symbol of the same AND requires, leaving the options that decide
// it: CONFIG_MPTCP && CONFIG_NET becomes CONFIG_MPTCP, as MPTCP needs NET.
// requires maps symbols to the ones they need enabled, as
// kconfig.Values.Requires tells. ORs, =y and =m tests and negations stay.
func Short(e *kcond.Expr, requires map[string][]string) *kcond.Expr {
	if e.Op != kcond.OpAnd && e.Op != kcond.OpOr {
		return e
	}
	args := make([]*kcond.Expr, len(e.Args))
	for i, a := range e.Args {
		args[i] = Short(a, requires)
	}
	if e.Op == kcond.OpOr {
		return kcond.Or(args...)
	}
	for i, x := range args {
		if x.Op != kcond.OpVar || x.State != kcond.Enabled {
			continue
		}
		// A term already dropped no longer counts, so that two symbols
		// requiring each other keep one.
		for j, y := range args {
			if j != i && y != nil && y.Op == kcond.OpVar && slices.Contains(requires[y.Name], x.Name) {
				args[i] = nil
				break
			}
		}
	}
	return kcond.And(slices.DeleteFunc(args, func(a *kcond.Expr) bool { return a == nil })...)
}

// The names of the verdicts.
const (
	Applies       = "applies"
	MayApply      = "unknown"
	NotApplicable = "not applicable"
)

// VerdictName names a verdict.
func VerdictName(v kcond.Tri) string {
	switch v {
	case kcond.True:
		return Applies
	case kcond.False:
		return NotApplicable
	}
	return MayApply
}

// Verdict tells whether code under the given condition is built by cfg:
// True when the condition holds, False when it does not and no file is
// unknown, Unknown otherwise.
func Verdict(cond *kcond.Expr, unknown bool, cfg kcond.Config) kcond.Tri {
	if cond == nil {
		return kcond.Unknown
	}
	v := cond.Eval(cfg)
	if v == kcond.False && unknown {
		return kcond.Unknown
	}
	return v
}
