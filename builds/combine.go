package builds

import (
	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/kbuild"
)

// File statuses of a crawl.
const (
	StatusBuilt    = "built"     // listed by a Makefile or #included by a listed source; Kbuild holds
	StatusUnlisted = "unlisted"  // neither listed by a Makefile the crawl follows nor #included by a listed source
	StatusNotBuilt = "not built" // another arch, the other word size, or a directory never entered outside arch/
	StatusHeader   = "header"
	StatusMissing  = "missing" // not found at any revision tried
)

// KbuildStatus is the status of a source file in a crawl, with its Kbuild
// condition when it is built.
func KbuildStatus(res *kbuild.Result, path string) (string, *kcond.Expr) {
	e, st := res.Lookup(path)
	switch st {
	case kbuild.Built:
		return StatusBuilt, e
	case kbuild.NotBuilt:
		return StatusNotBuilt, nil
	}
	return StatusUnlisted, nil
}

// FileCond is a changed file with its conditions.
type FileCond struct {
	Header bool
	Status string
	Kbuild *kcond.Expr // set when Status is built
	Region *kcond.Expr
}

// Combine is the condition of a change given its files. Sources, and
// headers built where the files including them are, count with their
// Kbuild condition ANDed with their region; a source that is not built
// contributes false, and one whose condition is unknown sets unknown. The
// other headers have no Kbuild condition and count only when no source
// changed, a built header being no source, through their region when it
// names a Kconfig symbol or is never compiled. cond is nil when no file has
// a known condition.
func Combine(files []FileCond) (cond *kcond.Expr, unknown bool) {
	var terms []*kcond.Expr
	sources := false
	for _, f := range files {
		if f.Header && f.Status != StatusBuilt {
			continue
		}
		sources = sources || !f.Header
		switch f.Status {
		case StatusBuilt:
			terms = append(terms, kcond.And(f.Kbuild, f.Region))
		case StatusNotBuilt:
			terms = append(terms, kcond.Const(false))
		default:
			unknown = true
		}
	}
	if !sources {
		for _, f := range files {
			switch {
			case f.Status == StatusBuilt: // counted above
			case f.Status == StatusNotBuilt || f.Region.IsConst(false):
				terms = append(terms, kcond.Const(false))
			case len(f.Region.Symbols()) > 0:
				terms = append(terms, f.Region)
			default:
				unknown = true
			}
		}
	}
	if len(terms) == 0 {
		return nil, true
	}
	return kcond.Or(terms...), unknown
}
