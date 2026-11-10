package builds

import (
	"slices"
	"strings"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/kbuild"
)

// pageSize is a page size an architecture may have, with the Kconfig
// symbol that selects it.
type pageSize struct {
	bytes  uint64
	symbol string
}

// pageSizes are the page sizes of the label arches that offer a choice;
// the others have 4 KiB pages. A symbol an older tree lacks is opaque
// there (see free), so the comparison stays unknown.
var pageSizes = map[string][]pageSize{
	"arm64":   {{4 << 10, "CONFIG_ARM64_4K_PAGES"}, {16 << 10, "CONFIG_ARM64_16K_PAGES"}, {64 << 10, "CONFIG_ARM64_64K_PAGES"}},
	"powerpc": {{4 << 10, "CONFIG_PPC_4K_PAGES"}, {16 << 10, "CONFIG_PPC_16K_PAGES"}, {64 << 10, "CONFIG_PPC_64K_PAGES"}, {256 << 10, "CONFIG_PPC_256K_PAGES"}},
	"loongarch": {{4 << 10, "CONFIG_4KB_2LEVEL"}, {4 << 10, "CONFIG_4KB_3LEVEL"}, {4 << 10, "CONFIG_4KB_4LEVEL"},
		{16 << 10, "CONFIG_16KB_2LEVEL"}, {16 << 10, "CONFIG_16KB_3LEVEL"}, {64 << 10, "CONFIG_64KB_2LEVEL"}, {64 << 10, "CONFIG_64KB_3LEVEL"}},
}

// moduleAtom is the atom of #ifdef MODULE, which Kbuild defines for the
// objects of a module.
const moduleAtom = "defined(MODULE)"

// Region returns the region of the changed lines of the file at path as
// build b reads it:
//
//   - A comparison of the page size holds or not with its architecture's
//     page sizes.
//   - MODULE is defined where b compiles the source into a module, and not
//     where it compiles it into the kernel; where b's crawl does not tell
//     either, the atom stays.
//   - A macro a -D flag of the source's object defines holds where b
//     compiles the source with the flag; elsewhere a header may still
//     define it, so the atom stays.
//
// Headers and sources b does not list keep the atoms of MODULE and -D
// macros.
func (b Build) Region(path string, region *kcond.Expr) *kcond.Expr {
	region = b.pageSize(region)
	if b.Kbuild == nil {
		return region
	}
	files, st := b.Kbuild.Lookup(path)
	if st != kbuild.Built {
		return region
	}
	for _, atom := range region.Opaque() {
		name, ok := strings.CutPrefix(atom, "defined(")
		if !ok {
			continue
		}
		if name, ok = strings.CutSuffix(name, ")"); !ok {
			continue
		}
		if atom == moduleAtom {
			builtin, module := b.Kbuild.Module(path)
			terms := []*kcond.Expr{kcond.And(builtin, kcond.With(region, atom, false)), kcond.And(module, kcond.With(region, atom, true))}
			if known, ok := kcond.Implies(files, kcond.Or(builtin, module)); !ok || !known {
				terms = append(terms, kcond.And(kcond.Not(builtin), kcond.Not(module), region))
			}
			region = kcond.Or(terms...)
		} else if set, unset := b.Kbuild.Define(path, name); !set.IsConst(false) {
			region = kcond.Or(kcond.And(set, kcond.With(region, atom, true)), kcond.And(unset, region))
		}
	}
	return region
}

// Plain writes the tests of e on symbols that cannot be m in build b
// plainly: X=y is X there, and X=m false. Kbuild conditions name both
// values of an option, obj-$(CONFIG_X) giving obj-y and obj-m, and the
// crawler cannot tell a bool from a tristate. A symbol b's Kconfig lacks
// is false when another Kconfig of the tree defines it, as $(CONFIG_X)
// expands to nothing and #ifdef CONFIG_X fails there; one no Kconfig
// defines stays, as do tristates and every symbol when the Kconfig could
// not be read.
func (b Build) Plain(e *kcond.Expr) *kcond.Expr {
	if b.Values == nil || e == nil {
		return e
	}
	// The gates are read before the rewrite, which drops the =m tests
	// of symbols this build cannot make modules, and after it, which
	// uncovers some.
	return b.shorten(b.gates(kcond.Rewrite(b.gates(e), func(v *kcond.Expr) *kcond.Expr {
		if kcond.IsSymbol(v.Name) && !b.Values.Defined(v.Name) && b.Defined[v.Name] {
			return kcond.Const(false)
		}
		if !kcond.IsSymbol(v.Name) || v.State == kcond.Enabled {
			return nil
		}
		if modular, known := b.Values.Modular(v.Name); !known || modular {
			return nil
		}
		if v.State == kcond.Module {
			return kcond.Const(false)
		}
		return kcond.Var(v.Name, kcond.Enabled)
	})))
}

// shorten drops from an OR a term that holds only with another term of
// the OR: Kconfig lets an option be on only with the options it depends on
// or selects, so CONFIG_JFFS2_FS || CONFIG_MTD is CONFIG_MTD, and so is
// (CONFIG_JFFS2_FS && CONFIG_X) || CONFIG_MTD or CONFIG_JFFS2_FS=m ||
// CONFIG_MTD. A tested value, CONFIG_MTD=y, is not what the option implies
// and absorbs nothing; a dropped term no longer absorbs, so that two
// options requiring each other keep one.
func (b Build) shorten(e *kcond.Expr) *kcond.Expr {
	if e == nil || e.Op == kcond.OpVar || e.Op == kcond.OpConst {
		return e
	}
	args := make([]*kcond.Expr, 0, len(e.Args))
	for _, a := range e.Args {
		args = append(args, b.shorten(a))
	}
	if e.Op != kcond.OpOr {
		return rebuild(e, args)
	}
	plain := map[string]bool{} // the options the OR tests enabled
	for _, a := range args {
		if a.Op == kcond.OpVar && a.State == kcond.Enabled {
			plain[a.Name] = true
		}
	}
	implied := func(t *kcond.Expr) bool {
		vars := []*kcond.Expr{t}
		if t.Op == kcond.OpAnd {
			vars = t.Args
		}
		for _, v := range vars {
			if v.Op != kcond.OpVar || !kcond.IsSymbol(v.Name) {
				continue
			}
			if on := append(b.Values.Requires(v.Name), b.Values.Selects(v.Name)...); slices.ContainsFunc(on, func(n string) bool { return plain[n] }) {
				return true
			}
		}
		return false
	}
	out := make([]*kcond.Expr, 0, len(args))
	for _, t := range args {
		if implied(t) {
			delete(plain, t.Name)
			continue
		}
		out = append(out, t)
	}
	return rebuild(e, out)
}

// rebuild is e with args for its arguments, e itself when they are its.
func rebuild(e *kcond.Expr, args []*kcond.Expr) *kcond.Expr {
	if slices.Equal(args, e.Args) {
		return e
	}
	switch e.Op {
	case kcond.OpAnd:
		return kcond.And(args...)
	case kcond.OpOr:
		return kcond.Or(args...)
	}
	return kcond.Not(args[0])
}

// gates drops from an AND the alternative X=y || Y=m that a term on Y of
// the AND settles: Kconfig lets a tristate Y be y only when the options it
// depends on are y, so Y=y makes the X y, and Y=m holds the alternative. A
// Kbuild condition carries such a gate for an object listed by
// obj-$(CONFIG_Y) in a directory entered through obj-$(CONFIG_X), which
// links its built-in objects only with X=y.
func (b Build) gates(e *kcond.Expr) *kcond.Expr {
	if e == nil || e.Op == kcond.OpVar || e.Op == kcond.OpConst {
		return e
	}
	names := map[string]bool{}
	if e.Op == kcond.OpAnd {
		for _, a := range e.Args {
			if a.Op == kcond.OpVar {
				names[a.Name] = true
			}
		}
	}
	args := make([]*kcond.Expr, 0, len(e.Args))
	for _, a := range e.Args {
		if !(a.Op == kcond.OpOr && b.gateSettled(a, names)) {
			args = append(args, b.gates(a))
		}
	}
	return rebuild(e, args)
}

// gateSettled tells whether or has a member Y=m, Y a tristate among names,
// whose other members hold once Y is y, with the options that are y then:
// what a y option selects, what a tristate at y depends on, and the bools
// a bool at y requires, since a bool is y wherever it is on but may be y
// on a tristate dependency at m. They are checked by evaluation, which
// proves them only when they have no negation.
func (b Build) gateSettled(or *kcond.Expr, names map[string]bool) bool {
	for i, m := range or.Args {
		if m.Op != kcond.OpVar || m.State != kcond.Module || !names[m.Name] || !b.Values.Tristate(m.Name) {
			continue
		}
		cfg := kcond.Config{}
		for todo := []string{m.Name}; len(todo) > 0; todo = todo[1:] {
			if n := todo[0]; cfg[n] == 0 {
				cfg[n] = 'y'
				if b.Values.Tristate(n) {
					todo = append(todo, b.Values.DependsOn(n)...)
				} else {
					for _, r := range b.Values.Requires(n) {
						if !b.Values.Tristate(r) {
							todo = append(todo, r)
						}
					}
				}
				todo = append(todo, b.Values.Selects(n)...)
			}
		}
		rest := kcond.Or(slices.Delete(slices.Clone(or.Args), i, i+1)...)
		if !negated(rest) && rest.Eval(cfg) == kcond.True {
			return true
		}
	}
	return false
}

// negated reports whether e has a negation.
func negated(e *kcond.Expr) bool {
	return e.Op == kcond.OpNot || slices.ContainsFunc(e.Args, negated)
}

// pageSize replaces the page size comparisons of region with what b's
// architecture gives.
func (b Build) pageSize(region *kcond.Expr) *kcond.Expr {
	return kcond.Subst(region, func(atom string) *kcond.Expr {
		holds, ok := kcond.PageSizeHolds(atom, 4<<10)
		if !ok {
			return nil
		}
		sizes, choice := pageSizes[b.Arch]
		if !choice {
			return kcond.Const(holds)
		}
		var terms []*kcond.Expr
		for _, s := range sizes {
			if holds, _ := kcond.PageSizeHolds(atom, s.bytes); holds {
				terms = append(terms, kcond.Var(s.symbol, kcond.Enabled))
			}
		}
		return kcond.Or(terms...)
	})
}
