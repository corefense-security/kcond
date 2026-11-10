package kbuild

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/corefense-security/kcond"
)

// cword is a word that is present under cond. opaque marks text produced
// by a make function this evaluator does not model.
type cword struct {
	cond   *kcond.Expr
	text   string
	opaque bool
}

// entry is one assignment to a variable, effective under cond. Simple
// (:=) assignments keep their expanded words, duplicates included so that
// flags pair up (see flags), recursive ones (=, += on a recursive
// variable) their raw text.
type entry struct {
	cond   *kcond.Expr
	raw    string
	words  []cword
	simple bool
}

type variable struct {
	entries []entry
	simple  bool
}

// frame is an open conditional: the conditions of its earlier branches and
// of the current one.
type frame struct {
	prev    []*kcond.Expr
	cur     *kcond.Expr
	sawElse bool
}

// rule is a rule that compiles an object of the Makefile's directory,
// target, from a source file elsewhere, source; either may hold the % of a
// pattern rule.
type rule struct {
	target, source string
	cond           *kcond.Expr
}

// evaluator runs one Makefile (and what it includes) symbolically: every
// variable value is a list of words, each present under a condition over
// Kconfig symbols.
type evaluator struct {
	fsys fs.FS
	dir  string // directory of the Makefile; "" for the top level
	// pre holds the variables the build passes to every Makefile. Like
	// make command-line variables, Makefile assignments do not change them.
	pre  map[string]string
	vars map[string]*variable
	// exported names the variables marked export, which make passes to
	// the Makefiles of subdirectories; parent is the top-level evaluator
	// they come from, and exports caches their values there.
	exported map[string]bool
	parent   *evaluator
	exports  map[string][]cword

	stack    []frame
	base     int         // the depth of stack where the file being run started
	ctx      *kcond.Expr // condition of the current line
	errors   []string
	file     string
	line     int
	mk       string // the Makefile run first, named in notes
	includes []string
	read     []string // every file run so far, in order: $(MAKEFILE_LIST)
	// expanding guards against recursive variables that refer to
	// themselves; unknown records a reference to a variable that is
	// neither assigned, predefined nor a Kconfig symbol.
	expanding map[string]bool
	unknown   bool
	// frozen is set once the Makefile is read; only then are variable
	// values cached, as later assignments could change them before.
	frozen bool
	cache  map[string][]cword
	// rules are the Makefile's rules that compile objects from a named
	// source, as xe's $(obj)/i915-display/%.o: $(srctree)/.../%.c does.
	rules []rule
	// statement is set while a line that is only an expression is
	// expanded, the place $(eval) runs.
	statement bool
	calls     int // the $(call)s being expanded
}

func newEvaluator(fsys fs.FS, dir string, pre map[string]string) *evaluator {
	return &evaluator{fsys: fsys, dir: dir, pre: pre, vars: map[string]*variable{}, exported: map[string]bool{},
		ctx: kcond.Const(true), expanding: map[string]bool{}}
}

func (e *evaluator) errorf(format string, args ...any) {
	e.errors = append(e.errors, fmt.Sprintf("%s:%d: %s", e.file, e.line, fmt.Sprintf(format, args...)))
}

// runtime lists variables make itself sets from how it was invoked. Their
// values are unknown even where a Makefile appends to them.
var runtime = map[string]bool{"MAKEFLAGS": true, "MAKECMDGOALS": true, "CURDIR": true, "MAKEFILE_LIST": true,
	".FEATURES": true, "MAKELEVEL": true, "MAKEOVERRIDES": true, "MFLAGS": true, ".VARIABLES": true}

// maxIncludes bounds include nesting.
const maxIncludes = 16

// maxCalls bounds the nesting of $(call)s being expanded.
const maxCalls = 16

// run processes a Makefile.
func (e *evaluator) run(file string) {
	data, err := fs.ReadFile(e.fsys, file)
	if err != nil {
		e.errors = append(e.errors, err.Error())
		return
	}
	saved := e.file
	if saved == "" {
		e.mk = file
	}
	e.file = file
	e.includes = append(e.includes, file)
	e.read = append(e.read, file)
	e.block(string(data), "")
	e.includes = e.includes[:len(e.includes)-1]
	e.file = saved
}

// block runs the lines of text as a block of their own: conditionals left
// open at its end are reported, as unterminated in where, and closed.
func (e *evaluator) block(text, where string) {
	savedLine, savedBase := e.line, e.base
	depth := len(e.stack)
	e.base = depth
	e.lines(text)
	if len(e.stack) > depth {
		e.errorf("%d unterminated conditional(s)%s", len(e.stack)-depth, where)
		e.stack = e.stack[:depth]
		e.update()
	}
	e.line, e.base = savedLine, savedBase
}

// logicalLines joins backslash continuations. It returns each logical line
// with the number of its first physical line.
func logicalLines(text string) ([]string, []int) {
	phys := strings.Split(text, "\n")
	var out []string
	var nums []int
	for i := 0; i < len(phys); i++ {
		start, l := i, phys[i]
		for continued(l) && i+1 < len(phys) {
			i++
			l = strings.TrimSuffix(strings.TrimRight(l, "\r"), "\\") + " " + strings.TrimLeft(phys[i], " \t")
		}
		out = append(out, strings.TrimRight(l, "\r"))
		nums = append(nums, start+1)
	}
	return out, nums
}

// continued reports whether l ends in an unescaped backslash.
func continued(l string) bool {
	l = strings.TrimRight(l, "\r")
	n := 0
	for n < len(l) && l[len(l)-1-n] == '\\' {
		n++
	}
	return n%2 == 1
}

// stripComment cuts a line at its first unescaped #.
func stripComment(l string) string {
	for i := 0; i < len(l); i++ {
		if l[i] == '#' && (i == 0 || l[i-1] != '\\') {
			return l[:i]
		}
	}
	return l
}

// definition is a define ... endef block being read.
type definition struct {
	head  string // what follows define: the name and an operator
	body  []string
	depth int // of define lines nested in the body
	live  bool
}

// directive is the first word of a line that is not a recipe line.
func directive(raw string) string {
	if strings.HasPrefix(raw, "\t") {
		return ""
	}
	if f := strings.Fields(raw); len(f) > 0 {
		return f[0]
	}
	return ""
}

func (e *evaluator) lines(text string) {
	ls, nums := logicalLines(text)
	inRule := false
	var def *definition
	var pending []rule // those of the last rule line, kept once a recipe follows
	for i, raw := range ls {
		e.line = nums[i]
		if def != nil {
			switch directive(raw) {
			case "define":
				def.depth++
			case "endef":
				if def.depth == 0 {
					e.define(def)
					def = nil
					continue
				}
				def.depth--
			}
			def.body = append(def.body, raw)
			continue
		}
		if strings.HasPrefix(raw, "\t") && inRule {
			e.rules, pending = append(e.rules, pending...), nil
			continue // recipe
		}
		l := strings.TrimSpace(stripComment(raw))
		if l == "" {
			continue
		}
		word, rest, _ := strings.Cut(l, " ")
		rest = strings.TrimSpace(rest)
		// A conditional inside a recipe leaves the recipe going.
		if !slices.Contains([]string{"ifdef", "ifndef", "ifeq", "ifneq", "else", "endif"}, word) {
			inRule, pending = false, nil
		}
		if (word == "export" || word == "override") && directive(rest) == "define" {
			if word == "export" && !e.dead() {
				if f := strings.Fields(rest); len(f) > 1 {
					e.exported[f[1]] = true
				}
			}
			word, rest = "define", strings.TrimSpace(strings.TrimPrefix(rest, "define"))
		}
		switch word {
		case "ifdef", "ifndef", "ifeq", "ifneq":
			e.push(word, rest)
			continue
		case "else":
			e.elseBranch(rest)
			continue
		case "endif":
			if len(e.stack) == e.base {
				e.errorf("endif without a conditional")
				continue
			}
			e.stack = e.stack[:len(e.stack)-1]
			e.update()
			continue
		case "define":
			def = &definition{head: rest, live: !e.dead()}
			continue
		case "endef", "vpath":
			continue
		case "include", "-include", "sinclude":
			if !e.dead() {
				e.include(rest)
			}
			continue
		case "export", "unexport", "override", "private":
			if word == "export" && !e.dead() {
				name := rest
				if n, _, _, ok := splitAssignment(rest); ok {
					name = n
				}
				for _, f := range strings.Fields(name) {
					e.exported[f] = true
				}
			}
			if rest == "" || !strings.ContainsAny(rest, "=") {
				continue
			}
			l = rest
		}
		if e.dead() {
			if isRule(l) {
				inRule = !targetVar(l)
			}
			continue
		}
		if isRule(l) {
			inRule = !targetVar(l)
			var recipe bool
			if pending, recipe = e.rule(l); recipe {
				e.rules, pending = append(e.rules, pending...), nil
			}
			continue
		}
		if name, op, value, ok := splitAssignment(l); ok {
			e.assign(name, op, value)
		} else if strings.HasPrefix(l, "$(") {
			// A line that is only an expression, such as
			// $(foreach ..., $(eval ...)), runs for its $(eval)s.
			saved := e.statement
			e.statement = true
			e.expand(l)
			e.statement = saved
		}
	}
}

// define assigns the body of a define block to its variable, recursive
// unless the define names another operator, as define X := does.
func (e *evaluator) define(d *definition) {
	f := strings.Fields(d.head)
	if !d.live || len(f) == 0 {
		return
	}
	op := "="
	if len(f) > 1 {
		op = f[1]
	}
	e.assign(f[0], op, strings.Join(d.body, "\n"))
}

// note records a word dropped from a list the crawler reads: make would
// expand it through a function this evaluator does not model.
func (e *evaluator) note(word, list string) {
	e.errors = append(e.errors, fmt.Sprintf("%s: opaque word %s in %s", e.mk, word, list))
}

// dead reports that the current line is in a branch that is never taken.
func (e *evaluator) dead() bool { return e.ctx.IsConst(false) }

// topLevel calls f for each byte of s outside $(...) and ${...}; f returns
// false to stop.
func topLevel(s string, f func(i int) bool) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '$' && i+1 < len(s) && (s[i+1] == '(' || s[i+1] == '{'):
			depth++
			i++
		case depth > 0 && (s[i] == '(' || s[i] == '{'):
			depth++
		case depth > 0 && (s[i] == ')' || s[i] == '}'):
			depth--
		case depth == 0:
			if !f(i) {
				return
			}
		}
	}
}

// topColon returns the index of the first colon of s outside references,
// or -1.
func topColon(s string) int {
	colon := -1
	topLevel(s, func(i int) bool {
		if s[i] == ':' {
			colon = i
			return false
		}
		return true
	})
	return colon
}

// isRule reports whether l is a rule (or target-specific variable): a
// top-level colon before any assignment operator.
func isRule(l string) bool {
	rule := false
	topLevel(l, func(i int) bool {
		switch l[i] {
		case '=':
			return false
		case ':':
			if i+1 < len(l) && (l[i+1] == '=' || l[i+1] == ':') {
				return false
			}
			rule = true
			return false
		}
		return true
	})
	return rule
}

// targetVar reports whether rule line l sets a target-specific variable,
// which, unlike a rule, takes no recipe.
func targetVar(l string) bool {
	rest, v := l[topColon(l)+1:], false
	topLevel(rest, func(i int) bool {
		switch rest[i] {
		case '=':
			v = true
		case ';':
		default:
			return true
		}
		return false
	})
	return v
}

// rule reads a rule line that compiles objects of the Makefile's
// directory from a source: each target $(obj)/X.o or $(obj)/PRE%SUF.o with
// the first prerequisite, a .c, .S, .rs or .s file holding the % when the
// target does, or another object of the directory, as lkdtm objcopies
// rodata_objcopy.o of rodata.o. A static pattern rule, targets: pattern: prerequisites,
// maps each target through its pattern instead, as the powerpc vDSO makes
// gettimeofday-32.o of gettimeofday.S. Only a rule with a recipe names its
// source; without one it adds prerequisites to a rule found by the
// object's own name. recipe tells whether the line carries the recipe
// itself, after a semicolon. Target-specific variables yield nothing.
func (e *evaluator) rule(l string) (rules []rule, recipe bool) {
	colon := topColon(l)
	targets, rest := l[:colon], l[colon+1:]
	variable, static, end := false, -1, len(rest)
	topLevel(rest, func(i int) bool {
		switch rest[i] {
		case ':':
			if static < 0 {
				static = i
				return true
			}
			variable = true
		case '=':
			variable = true
		case ';':
			end, recipe = i, true
		default:
			return true
		}
		return false
	})
	if variable || e.dir == "" {
		return nil, false
	}
	pattern := ""
	if static >= 0 {
		pattern = strings.TrimSpace(e.text(rest[:static]))
		rest = rest[static+1:]
		end -= static + 1
	}
	prereqs, _, _ := strings.Cut(rest[:end], "|")
	ps := e.expand(prereqs)
	if len(ps) == 0 || ps[0].opaque {
		return nil, false
	}
	src := cleanPath(ps[0].text)
	object := path.Ext(src) == ".o" && strings.HasPrefix(src, e.dir+"/")
	if (!slices.Contains(sourceExts, path.Ext(src)) && !object) || !fs.ValidPath(src) {
		return nil, false
	}
	for _, t := range e.expand(targets) {
		tgt, from := cleanPath(t.text), src
		if pattern != "" {
			if !matches(pattern, t.text) {
				continue
			}
			from = cleanPath(patsubst(pattern, ps[0].text, t.text))
		}
		if t.opaque || !strings.HasPrefix(tgt, e.dir+"/") || !strings.HasSuffix(tgt, ".o") ||
			strings.Contains(tgt, "%") != strings.Contains(from, "%") {
			continue
		}
		rules = append(rules, rule{tgt, from, kcond.And(e.ctx, t.cond, ps[0].cond)})
	}
	return rules, recipe
}

// splitAssignment splits NAME op VALUE for =, :=, ::=, :::=, ?=, += and !=.
func splitAssignment(l string) (name, op, value string, ok bool) {
	eq := -1
	topLevel(l, func(i int) bool {
		if l[i] == '=' {
			eq = i
			return false
		}
		return true
	})
	if eq < 0 {
		return "", "", "", false
	}
	start := eq
	for start > 0 && strings.IndexByte(":+?!", l[start-1]) >= 0 {
		start--
	}
	name = strings.TrimSpace(l[:start])
	if name == "" {
		return "", "", "", false
	}
	return name, l[start : eq+1], strings.TrimSpace(l[eq+1:]), true
}

func (e *evaluator) assign(lhs, op, value string) {
	for _, n := range e.expandRaw(lhs) {
		if n.opaque && !e.dead() {
			e.errorf("opaque variable name %s not assigned", abbreviate(lhs, 60))
		}
		if n.opaque || n.text == "" || strings.ContainsAny(n.text, " \t") {
			continue
		}
		name := n.text
		if _, ok := e.pre[name]; ok || runtime[name] {
			continue
		}
		c := kcond.And(e.ctx, n.cond)
		v := e.vars[name]
		if v == nil {
			v = &variable{}
			// Appending to an exported variable extends its inherited
			// value.
			if op == "+=" && e.parent != nil && e.parent.exported[name] {
				v.entries = []entry{{cond: kcond.Const(true), words: e.parent.exportedValue(name), simple: true}}
				v.simple = true
			}
			e.vars[name] = v
		}
		delete(e.cache, name)
		switch op {
		case "=", "?=":
			if op == "?=" {
				// Only where no earlier assignment set the variable.
				var set []*kcond.Expr
				for _, en := range v.entries {
					set = append(set, en.cond)
				}
				if c = kcond.And(c, kcond.Not(kcond.Or(set...))); c.IsConst(false) {
					continue
				}
			}
			v.entries = append(e.without(v.entries, c), entry{cond: c, raw: value})
			v.simple = false
		case ":=", "::=", ":::=":
			words := e.expandRaw(value)
			v.entries = append(e.without(v.entries, c), entry{cond: c, words: words, simple: true})
			v.simple = true
		case "+=":
			if v.simple {
				v.entries = append(v.entries, entry{cond: c, words: e.expandRaw(value), simple: true})
			} else {
				v.entries = append(v.entries, entry{cond: c, raw: value})
			}
		}
	}
}

// without restricts entries to where c does not hold, as an assignment
// under c replaces the value only there.
func (e *evaluator) without(entries []entry, c *kcond.Expr) []entry {
	var out []entry
	nc := kcond.Not(c)
	for _, en := range entries {
		en.cond = kcond.And(en.cond, nc)
		if en.cond.IsConst(false) {
			continue
		}
		out = append(out, en)
	}
	return out
}

// value returns the words of a variable.
func (e *evaluator) value(name string) []cword {
	if v := e.vars[name]; v != nil && len(v.entries) > 0 {
		if ws, ok := e.cache[name]; ok && e.frozen {
			return ws
		}
		if e.expanding[name] {
			return nil
		}
		e.expanding[name] = true
		var out []cword
		for _, en := range v.entries {
			ws := en.words
			if !en.simple {
				ws = e.expand(en.raw)
			}
			for _, w := range ws {
				w.cond = kcond.And(w.cond, en.cond)
				out = append(out, w)
			}
		}
		delete(e.expanding, name)
		out = merge(out)
		if e.frozen {
			if e.cache == nil {
				e.cache = map[string][]cword{}
			}
			e.cache[name] = out
		}
		return out
	}
	if name == "MAKEFILE_LIST" {
		return literal(strings.Join(e.read, " "))
	}
	if v, ok := e.pre[name]; ok {
		return literal(v)
	}
	if e.parent != nil && e.parent.exported[name] {
		return e.parent.exportedValue(name)
	}
	if kcond.IsSymbol(name) {
		return []cword{{cond: kcond.Var(name, kcond.Builtin), text: "y"}, {cond: kcond.Var(name, kcond.Module), text: "m"}}
	}
	e.unknown = true
	return nil
}

// flags returns the -I, -iquote, -D and -include flags of a variable of
// compiler flags. Its words are read in order, duplicates kept, so that
// -I dir pairs up.
func (e *evaluator) flags(name string) []flag {
	v := e.vars[name]
	if v == nil {
		return nil
	}
	var ws []cword
	for _, en := range v.entries {
		words := en.words
		if !en.simple {
			words = e.expandRaw(en.raw)
		}
		for _, w := range words {
			w.cond = kcond.And(w.cond, en.cond)
			ws = append(ws, w)
		}
	}
	var out []flag
	for i := 0; i < len(ws); i++ {
		w := ws[i]
		if w.opaque {
			continue
		}
		f := flag{cond: w.cond}
		switch t := w.text; {
		case t == "-I" || t == "-iquote" || t == "-D" || t == "-include":
			if i+1 == len(ws) || ws[i+1].opaque {
				continue
			}
			i++
			f.kind = map[string]flagKind{"-D": defineMacro, "-include": includedFile}[t]
			f.arg, f.cond = ws[i].text, kcond.And(f.cond, ws[i].cond)
		case strings.HasPrefix(t, "-iquote"):
			f.arg = t[len("-iquote"):]
		case strings.HasPrefix(t, "-I"):
			f.arg = t[2:]
		case strings.HasPrefix(t, "-D"):
			f.kind, f.arg = defineMacro, t[2:]
		default:
			continue
		}
		if f.kind == defineMacro {
			f.arg, _, _ = strings.Cut(f.arg, "=")
		} else {
			f.arg = cleanPath(f.arg)
		}
		if f.arg != "" && (f.kind == defineMacro || fs.ValidPath(f.arg)) {
			out = append(out, f)
		}
	}
	return out
}

// maxRelax bounds the opaque atoms relaxed away exactly in an exported
// word's condition; relaxing is exponential in them.
const maxRelax = 6

// exportedValue is the value an exported variable of the top level has in
// other Makefiles. As for the root lists, conditions on make variables this
// evaluator does not model are relaxed away, approximately when they are
// many, as behind the top Makefile's own conditionals.
func (e *evaluator) exportedValue(name string) []cword {
	if ws, ok := e.exports[name]; ok {
		return ws
	}
	var ws []cword
	for _, w := range e.value(name) {
		if len(w.cond.Opaque()) > maxRelax {
			w.cond = loosen(w.cond, true)
		} else {
			w.cond = kcond.Relax(w.cond)
		}
		ws = append(ws, w)
	}
	if e.exports == nil {
		e.exports = map[string][]cword{}
	}
	e.exports[name] = ws
	return ws
}

// loosen drops the opaque atoms of e, taking each occurrence in the
// polarity that makes e true when positive: a weaker condition than
// kcond.Relax gives, computed in one pass.
func loosen(e *kcond.Expr, positive bool) *kcond.Expr {
	switch e.Op {
	case kcond.OpVar:
		if !kcond.IsSymbol(e.Name) {
			return kcond.Const(positive)
		}
	case kcond.OpNot:
		return kcond.Not(loosen(e.Args[0], !positive))
	case kcond.OpAnd, kcond.OpOr:
		args := make([]*kcond.Expr, len(e.Args))
		for i, a := range e.Args {
			args[i] = loosen(a, positive)
		}
		if e.Op == kcond.OpAnd {
			return kcond.And(args...)
		}
		return kcond.Or(args...)
	}
	return e
}

func literal(s string) []cword {
	var out []cword
	for _, f := range strings.Fields(s) {
		out = append(out, cword{cond: kcond.Const(true), text: f})
	}
	return out
}

// merge ORs the conditions of equal words, keeping their first order, and
// drops words that are never present.
func merge(ws []cword) []cword {
	idx := map[string]int{}
	var out []cword
	for _, w := range ws {
		if w.cond.IsConst(false) {
			continue
		}
		if i, ok := idx[w.text]; ok {
			out[i].cond = kcond.Or(out[i].cond, w.cond)
			out[i].opaque = out[i].opaque || w.opaque
			continue
		}
		idx[w.text] = len(out)
		out = append(out, w)
	}
	return out
}

// maxAlternatives bounds the words one glued word can expand to.
const maxAlternatives = 4096

// expand evaluates text into words.
func (e *evaluator) expand(s string) []cword {
	return merge(e.expandRaw(s))
}

// maxGlued bounds the conditional alternatives a word made of a reference
// and adjacent text can expand to. Object names glue to a few, such as
// obj-$(CONFIG_X) or foo-$(BITS).o; more come from strings built option by
// option, such as arch/riscv's -march=$(riscv-march-y), whose alternatives
// double with each line. Beyond the bound the word becomes opaque.
const maxGlued = 16

// expandRaw evaluates text. Text glued to a reference applies to each word
// of its value (pre$(LIST).o works like addprefix and addsuffix), and an
// empty alternative is kept so that obj-$(CONFIG_X) also yields obj- when X
// is off.
func (e *evaluator) expandRaw(s string) []cword {
	var out []cword
	cur := []cword{{cond: kcond.Const(true)}}
	var ref, text bool // the current word has a reference, literal text
	flush := func() {
		if ref && text && conditional(cur) > maxGlued {
			cur = []cword{{cond: kcond.Const(true), text: "$(...)", opaque: true}}
		}
		for _, w := range cur {
			if w.text != "" {
				out = append(out, w)
			}
		}
		cur = []cword{{cond: kcond.Const(true)}}
		ref, text = false, false
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			flush()
			i++
		case c == '$' && i+1 < len(s):
			words, n := e.reference(s[i:])
			cur = glue(cur, words)
			ref = true
			i += n
		default:
			// s[i] is literal, even a $ that ends s.
			j := i + 1
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '$' {
				j++
			}
			for k := range cur {
				cur[k].text += s[i:j]
			}
			text = true
			i = j
		}
	}
	flush()
	return out
}

// conditional counts the words that are not always present.
func conditional(ws []cword) int {
	n := 0
	for _, w := range ws {
		if !w.cond.IsConst(true) {
			n++
		}
	}
	return n
}

// glue appends each word of ref to each alternative of cur. ref's empty
// alternative holds where none of its words does.
func glue(cur, ref []cword) []cword {
	alts := slices.Clone(ref)
	var conds []*kcond.Expr
	for _, w := range ref {
		conds = append(conds, w.cond)
	}
	if none := kcond.Not(kcond.Or(conds...)); !none.IsConst(false) {
		alts = append(alts, cword{cond: none})
	}
	var out []cword
	for _, a := range cur {
		for _, b := range alts {
			if len(out) == maxAlternatives {
				return out
			}
			c := kcond.And(a.cond, b.cond)
			if c.IsConst(false) {
				continue
			}
			out = append(out, cword{cond: c, text: a.text + b.text, opaque: a.opaque || b.opaque})
		}
	}
	return out
}

// reference evaluates the reference at the start of s ($$, $X, $(...) or
// ${...}) and returns its words and length.
func (e *evaluator) reference(s string) ([]cword, int) {
	switch s[1] {
	case '$':
		return []cword{{cond: kcond.Const(true), text: "$"}}, 2
	case '(', '{':
	default:
		return nil, 2 // automatic variables such as $@ only exist in recipes
	}
	end, n := e.span(s)
	if end < 0 {
		return []cword{{cond: kcond.Const(true), text: s, opaque: true}}, n
	}
	return e.evalBody(s[2:end]), n
}

// span finds the end of the reference $(...) or ${...} at the start of s:
// the index of its closing parenthesis and its length, or -1 and len(s)
// when it is not closed.
func (e *evaluator) span(s string) (end, n int) {
	open, closing := s[1], byte(')')
	if open == '{' {
		closing = '}'
	}
	depth := 0
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case open:
			depth++
		case closing:
			depth--
		}
		if depth == 0 {
			return i, i + 1
		}
	}
	return -1, len(s)
}

var makeFunctions = map[string]bool{
	"subst": true, "patsubst": true, "strip": true, "findstring": true, "filter": true, "filter-out": true,
	"sort": true, "word": true, "wordlist": true, "words": true, "firstword": true, "lastword": true,
	"dir": true, "notdir": true, "suffix": true, "basename": true, "addsuffix": true, "addprefix": true,
	"join": true, "wildcard": true, "realpath": true, "abspath": true, "if": true, "or": true, "and": true,
	"foreach": true, "file": true, "call": true, "value": true, "eval": true, "origin": true, "flavor": true,
	"shell": true, "error": true, "warning": true, "info": true, "guile": true, "intcmp": true, "let": true,
}

func (e *evaluator) evalBody(body string) []cword {
	if name, args, ok := strings.Cut(body, " "); ok && makeFunctions[name] {
		return e.function(name, splitArgs(args))
	}
	if name, args, ok := strings.Cut(body, "\t"); ok && makeFunctions[name] {
		return e.function(name, splitArgs(args))
	}
	// Substitution reference $(VAR:a=b).
	if colon := topColon(body); colon >= 0 && strings.Contains(body[colon:], "=") {
		from, to, _ := strings.Cut(body[colon+1:], "=")
		from, to = e.text(from), e.text(to)
		if !strings.Contains(from, "%") {
			from, to = "%"+from, "%"+to
		}
		var out []cword
		for _, w := range e.varRef(body[:colon]) {
			w.text = patsubst(from, to, w.text)
			out = append(out, w)
		}
		return out
	}
	return e.varRef(body)
}

// varRef evaluates a variable reference whose name may itself contain
// references.
func (e *evaluator) varRef(name string) []cword {
	var out []cword
	for _, n := range e.expandRaw(name) {
		if n.opaque {
			out = append(out, cword{cond: kcond.Const(true), text: "$(" + name + ")", opaque: true})
			continue
		}
		for _, w := range e.value(strings.TrimSpace(n.text)) {
			w.cond = kcond.And(w.cond, n.cond)
			out = append(out, w)
		}
	}
	return out
}

// splitArgs splits function arguments at top-level commas.
func splitArgs(s string) []string {
	var args []string
	start := 0
	topLevel(s, func(i int) bool {
		if s[i] == ',' {
			args = append(args, s[start:i])
			start = i + 1
		}
		return true
	})
	return append(args, s[start:])
}

// text joins the words of an argument that holds unconditionally.
func (e *evaluator) text(arg string) string { return joinWords(e.expand(arg)) }

func (e *evaluator) function(name string, args []string) []cword {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	mapWords := func(ws []cword, f func(string) string) []cword {
		var out []cword
		for _, w := range ws {
			w.text = f(w.text)
			out = append(out, w)
		}
		return out
	}
	switch name {
	case "subst":
		from := e.text(arg(0))
		if from == "" {
			return e.expand(arg(2))
		}
		tos := e.expand(arg(1))
		if conditional(tos) == 0 {
			to := e.text(arg(1))
			return mapWords(e.expand(arg(2)), func(s string) string { return strings.ReplaceAll(s, from, to) })
		}
		// The replacement depends on the configuration, as in net/l2tp's
		// obj-$(subst y,$(CONFIG_L2TP),$(CONFIG_L2TP_V3)): substitute
		// each of its alternatives, the empty one where none holds.
		alts := glue([]cword{{cond: kcond.Const(true)}}, tos)
		var out []cword
		for _, w := range e.expand(arg(2)) {
			if !strings.Contains(w.text, from) {
				out = append(out, w)
				continue
			}
			for _, t := range alts {
				c := kcond.And(w.cond, t.cond)
				if c.IsConst(false) {
					continue
				}
				out = append(out, cword{cond: c, text: strings.ReplaceAll(w.text, from, t.text), opaque: w.opaque || t.opaque})
			}
		}
		return out
	case "patsubst":
		from, to := strings.TrimSpace(e.text(arg(0))), strings.TrimSpace(e.text(arg(1)))
		return mapWords(e.expand(arg(2)), func(s string) string { return patsubst(from, to, s) })
	case "addprefix", "addsuffix":
		var out []cword
		for _, a := range e.expand(arg(0)) {
			for _, w := range e.expand(arg(1)) {
				text := a.text + w.text
				if name == "addsuffix" {
					text = w.text + a.text
				}
				out = append(out, cword{cond: kcond.And(a.cond, w.cond), text: text, opaque: a.opaque || w.opaque})
			}
		}
		return out
	case "filter", "filter-out":
		pats := strings.Fields(e.text(arg(0)))
		var out []cword
		for _, w := range e.expand(arg(1)) {
			hit := slices.ContainsFunc(pats, func(p string) bool { return matches(p, w.text) })
			if hit == (name == "filter") {
				out = append(out, w)
			}
		}
		return out
	case "findstring":
		// The text where one of the words holds it: obj-$(findstring y,
		// $(CONFIG_A) $(CONFIG_B)) is obj-y where either is y.
		find := e.text(arg(0))
		ws := e.expand(arg(1))
		if find == "" || slices.ContainsFunc(ws, func(w cword) bool { return w.opaque }) {
			break
		}
		var cs []*kcond.Expr
		for _, w := range ws {
			if strings.Contains(w.text, find) {
				cs = append(cs, w.cond)
			}
		}
		return []cword{{cond: kcond.Or(cs...), text: find}}
	case "strip", "sort":
		return e.expand(arg(0))
	case "firstword", "lastword":
		ws := e.expandRaw(arg(0))
		if !fixed(ws) {
			break // which word is first depends on the configuration
		}
		if len(ws) == 0 {
			return nil
		}
		if name == "firstword" {
			return ws[:1]
		}
		return ws[len(ws)-1:]
	case "abspath", "realpath":
		// Paths stay in the tree, as $(srctree) is ".".
		return mapWords(e.expand(arg(0)), cleanPath)
	case "notdir":
		return mapWords(e.expand(arg(0)), path.Base)
	case "dir":
		return mapWords(e.expand(arg(0)), func(s string) string { return path.Dir(s) + "/" })
	case "basename":
		return mapWords(e.expand(arg(0)), func(s string) string { return strings.TrimSuffix(s, path.Ext(s)) })
	case "suffix":
		return mapWords(e.expand(arg(0)), path.Ext)
	case "if":
		// Both branches are expanded, so an $(eval) in them must not run.
		saved := e.statement
		e.statement = false
		defer func() { e.statement = saved }()
		cond, opaque := e.nonEmpty(e.expand(arg(0)))
		if opaque {
			cond = kcond.Var("$(if "+strings.TrimSpace(arg(0))+")", kcond.Enabled)
		}
		var out []cword
		for _, w := range e.expand(arg(1)) {
			w.cond = kcond.And(w.cond, cond)
			out = append(out, w)
		}
		for _, w := range e.expand(arg(2)) {
			w.cond = kcond.And(w.cond, kcond.Not(cond))
			out = append(out, w)
		}
		return out
	case "or":
		// The first argument that is not empty: each one's words under
		// the condition that those before it were empty.
		var out []cword
		before := kcond.Const(true)
		for _, a := range args {
			ws := e.expand(a)
			cond, opaque := e.nonEmpty(ws)
			if opaque {
				cond = kcond.Var("$(or "+strings.TrimSpace(a)+")", kcond.Enabled)
			}
			for _, w := range ws {
				w.cond = kcond.And(w.cond, before)
				out = append(out, w)
			}
			if before = kcond.And(before, kcond.Not(cond)); before.IsConst(false) {
				break
			}
		}
		return out
	case "foreach":
		var out []cword
		e.forEach(arg(0), arg(1), func(w cword) {
			for _, b := range e.expand(arg(2)) {
				b.cond = kcond.And(b.cond, w.cond)
				out = append(out, b)
			}
		})
		return out
	case "wildcard":
		var out []cword
		for _, p := range strings.Fields(e.text(arg(0))) {
			matches, _ := fs.Glob(e.fsys, cleanPath(p))
			for _, m := range matches {
				out = append(out, cword{cond: kcond.Const(true), text: m})
			}
		}
		return out
	case "call":
		if text, ok := e.callText(args); ok {
			e.calls++
			defer func() { e.calls-- }()
			return e.expand(text)
		}
	case "eval":
		text := strings.Join(args, ",")
		if !e.statement || e.frozen {
			e.errorf("$(eval %s) not evaluated", abbreviate(strings.TrimSpace(text), 60))
			return nil
		}
		e.eval(text)
		return nil
	case "error", "warning", "info":
		return nil
	}
	return []cword{{cond: kcond.Const(true), text: "$(" + name + " " + strings.Join(args, ",") + ")", opaque: true}}
}

// forEach binds the variable named by v to each word of list in turn,
// under the word's condition, so that an $(eval) runs under it, and calls
// f with the word.
func (e *evaluator) forEach(v, list string, f func(w cword)) {
	v = strings.TrimSpace(e.text(v))
	saved := e.vars[v]
	for _, w := range e.expand(list) {
		e.vars[v] = &variable{entries: []entry{{cond: kcond.Const(true), words: []cword{{cond: kcond.Const(true), text: w.text}}, simple: true}}, simple: true}
		clear(e.cache) // a helper variable of the body may hold the old word
		e.stack = append(e.stack, frame{cur: w.cond})
		e.update()
		f(w)
		e.stack = e.stack[:len(e.stack)-1]
		e.update()
	}
	clear(e.cache)
	if saved == nil {
		delete(e.vars, v)
	} else {
		e.vars[v] = saved
	}
}

// callText returns the text $(call name,args...) expands: the raw value of
// the macro with its parameters replaced by the raw text of the arguments,
// so that conditional arguments keep their conditions when the text is
// expanded. ok is false for a macro this evaluator lacks, one a Makefile
// it does not run defines, or one defined only under a condition, and
// beyond maxCalls nested calls, as a macro that calls itself under $(if),
// whose branches are both expanded, would never end.
func (e *evaluator) callText(args []string) (string, bool) {
	name := strings.TrimSpace(e.text(args[0]))
	v := e.vars[name]
	if e.calls >= maxCalls || v == nil || len(v.entries) != 1 || v.entries[0].simple || !v.entries[0].cond.IsConst(true) {
		return "", false
	}
	return substParams(v.entries[0].raw, name, args[1:]), true
}

// substParams replaces the references to the parameters of a call in body:
// $(0) by the macro's name, $(n), ${n} and $n by the nth argument, empty
// when there is none. $$ stays.
func substParams(body, name string, args []string) string {
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] != '$' || i+1 == len(body) {
			b.WriteByte(body[i])
			continue
		}
		n, end := -1, i+1
		switch c := body[i+1]; {
		case c == '$':
			b.WriteString("$$")
			i++
			continue
		case c >= '0' && c <= '9':
			n = int(c - '0')
		case c == '(' || c == '{':
			j := i + 2
			for j < len(body) && body[j] >= '0' && body[j] <= '9' {
				j++
			}
			if closing := map[byte]byte{'(': ')', '{': '}'}[c]; j > i+2 && j < len(body) && body[j] == closing {
				n, _ = strconv.Atoi(body[i+2 : j])
				end = j
			}
		}
		if n < 0 {
			b.WriteByte('$')
			continue
		}
		if n == 0 {
			b.WriteString(name)
		} else if n <= len(args) {
			b.WriteString(args[n-1])
		}
		i = end
	}
	return b.String()
}

// eval runs text as Makefile lines under the current condition, as
// $(eval) does once it has expanded the text. $(eval $(foreach
// v,list,body)) evaluates body for each word, under its condition.
func (e *evaluator) eval(text string) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "$(foreach ") {
		if end, _ := e.span(text); end == len(text)-1 {
			if args := splitArgs(text[len("$(foreach "):end]); len(args) == 3 {
				e.forEach(args[0], args[1], func(cword) { e.eval(args[2]) })
				return
			}
		}
	}
	t, ok := e.evalText(text)
	if !ok {
		e.errorf("$(eval %s) not evaluated", abbreviate(text, 60))
		return
	}
	unknown := e.unknown
	e.block(t, " in $(eval)")
	e.unknown = unknown
}

// evalText expands text for $(eval). A reference whose value holds
// unconditionally is replaced by it, as make does, so that the lines read
// a loop variable before it goes; one with a conditional or opaque value
// is left for the lines to expand symbolically, which reads the same lines
// unless the value holds $, #, :, = or a newline. ok is false when a
// $(call) names a macro callText cannot expand, or a reference is not
// closed.
func (e *evaluator) evalText(text string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '$' || i+1 == len(text) {
			b.WriteByte(text[i])
			continue
		}
		switch text[i+1] {
		case '$':
			b.WriteByte('$')
			i++
			continue
		case '(', '{':
		default:
			b.WriteByte('$')
			continue
		}
		end, n := e.span(text[i:])
		if end < 0 {
			return "", false
		}
		ref := text[i : i+n]
		if body, ok := strings.CutPrefix(ref[2:end], "call "); ok {
			t, ok := e.callText(splitArgs(body))
			if !ok {
				return "", false
			}
			e.calls++
			t, ok = e.evalText(t)
			e.calls--
			if !ok {
				return "", false
			}
			b.WriteString(t)
		} else if ws := e.expand(ref); fixed(ws) {
			b.WriteString(joinWords(ws))
		} else {
			b.WriteString(ref)
		}
		i += n - 1
	}
	return b.String(), true
}

// fixed reports whether words hold in every configuration.
func fixed(ws []cword) bool {
	return !slices.ContainsFunc(ws, func(w cword) bool { return w.opaque || !w.cond.IsConst(true) })
}

// nonEmpty is the condition under which words is not empty.
// assigned is where v has a value as ifdef tests it, without expanding a
// recursive entry, so that FOO = $(EMPTY) is defined; nil when a word is
// opaque.
func (e *evaluator) assigned(v *variable) *kcond.Expr {
	var cs []*kcond.Expr
	for _, en := range v.entries {
		set := kcond.Const(strings.TrimSpace(en.raw) != "")
		if en.simple {
			if set, _ = e.nonEmpty(en.words); set == nil {
				return nil
			}
		}
		cs = append(cs, kcond.And(en.cond, set))
	}
	return kcond.Or(cs...)
}

func (e *evaluator) nonEmpty(ws []cword) (*kcond.Expr, bool) {
	var cs []*kcond.Expr
	for _, w := range ws {
		if w.opaque {
			return nil, true
		}
		cs = append(cs, w.cond)
	}
	return kcond.Or(cs...), false
}

// matches reports whether word matches a make pattern with one %.
func matches(pattern, word string) bool {
	pre, suf, ok := strings.Cut(pattern, "%")
	if !ok {
		return pattern == word
	}
	return len(word) >= len(pre)+len(suf) && strings.HasPrefix(word, pre) && strings.HasSuffix(word, suf)
}

// patsubst replaces word if it matches from, carrying the % stem to to.
func patsubst(from, to, word string) string {
	pre, suf, ok := strings.Cut(from, "%")
	if !ok {
		if word == from {
			return to
		}
		return word
	}
	if !matches(from, word) {
		return word
	}
	stem := word[len(pre) : len(word)-len(suf)]
	return strings.Replace(to, "%", stem, 1)
}

// cleanPath turns a path from a Makefile ($(srctree)/x, ./x) into a path
// in the tree.
func cleanPath(p string) string {
	p = path.Clean(p)
	return strings.TrimPrefix(p, "./")
}

func (e *evaluator) include(rest string) {
	if len(e.includes) >= maxIncludes {
		e.errorf("includes nested too deep")
		return
	}
	for _, w := range e.expand(rest) {
		if w.opaque {
			continue
		}
		p := cleanPath(w.text)
		if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") || slices.Contains(e.includes, p) {
			continue
		}
		if st, err := fs.Stat(e.fsys, p); err != nil || st.IsDir() {
			continue
		}
		// The included file runs under the condition of the include line
		// and of its word, as in include $(LIST) of a conditional list.
		e.stack = append(e.stack, frame{cur: w.cond})
		e.update()
		e.run(p)
		e.stack = e.stack[:len(e.stack)-1]
		e.update()
	}
}

// update recomputes the condition of the current line.
func (e *evaluator) update() {
	var terms []*kcond.Expr
	for _, f := range e.stack {
		for _, p := range f.prev {
			terms = append(terms, kcond.Not(p))
		}
		terms = append(terms, f.cur)
	}
	e.ctx = kcond.And(terms...)
}

func (e *evaluator) push(kind, rest string) {
	e.stack = append(e.stack, frame{cur: e.condition(kind, rest)})
	e.update()
}

func (e *evaluator) elseBranch(rest string) {
	if len(e.stack) == e.base {
		e.errorf("else without a conditional")
		return
	}
	top := &e.stack[len(e.stack)-1]
	if top.sawElse {
		e.errorf("else after else")
		return
	}
	top.prev = append(top.prev, top.cur)
	kind, args, _ := strings.Cut(rest, " ")
	switch kind {
	case "ifdef", "ifndef", "ifeq", "ifneq":
		// A $(foreach) in the condition pushes frames, which can move
		// the stack top points into.
		c := e.condition(kind, strings.TrimSpace(args))
		e.stack[len(e.stack)-1].cur = c
	default:
		top.cur = kcond.Const(true)
		top.sawElse = true
	}
	e.update()
}

// condition evaluates an ifdef/ifndef/ifeq/ifneq line. Conditions that
// depend on variables this evaluator does not know become opaque atoms.
func (e *evaluator) condition(kind, rest string) *kcond.Expr {
	e.unknown = false
	var c *kcond.Expr
	switch kind {
	case "ifdef", "ifndef":
		name := strings.TrimSpace(e.text(rest))
		if v := e.vars[name]; v != nil && len(v.entries) > 0 {
			c = e.assigned(v)
		} else if ws := e.value(name); !e.unknown {
			c, _ = e.nonEmpty(ws)
		}
		if c == nil {
			c = kcond.Var("defined("+name+")", kcond.Enabled)
		}
	default:
		a, b, ok := splitIfeq(rest)
		if !ok {
			e.errorf("bad %s condition %q", kind, rest)
			return kcond.Const(false)
		}
		c = e.equal(a, b)
	}
	if kind == "ifndef" || kind == "ifneq" {
		c = kcond.Not(c)
	}
	return c
}

// splitIfeq parses (a,b), "a" "b", 'a' 'b' and mixed quotes.
func splitIfeq(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		args := splitArgs(s[1 : len(s)-1])
		if len(args) != 2 {
			return "", "", false
		}
		return strings.TrimSpace(args[0]), strings.TrimSpace(args[1]), true
	}
	var parts []string
	for len(s) > 0 && len(parts) < 2 {
		q := s[0]
		if q != '"' && q != '\'' {
			return "", "", false
		}
		end := strings.IndexByte(s[1:], q)
		if end < 0 {
			return "", "", false
		}
		parts = append(parts, s[1:end+1])
		s = strings.TrimSpace(s[end+2:])
	}
	if len(parts) != 2 || s != "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// equal is the condition under which the expansions of a and b are the same
// list of words. One side must not depend on Kconfig symbols; otherwise, when
// a side uses an unknown variable, or when symbols are compared to text other
// than their y and m, the condition is an opaque atom.
func (e *evaluator) equal(a, b string) *kcond.Expr {
	atom := kcond.Var(a+" == "+b, kcond.Enabled)
	e.unknown = false
	wa, wb := e.expand(a), e.expand(b)
	if e.unknown {
		return atom
	}
	switch {
	case fixed(wa) && fixed(wb):
		return kcond.Const(joinWords(wa) == joinWords(wb))
	case fixed(wb):
	case fixed(wa):
		wa, wb = wb, wa
	default:
		return atom
	}
	for _, w := range wa {
		if w.opaque {
			return atom
		}
	}
	// wa varies, wb is fixed: each word of wb must be present and every
	// other word of wa absent.
	want := map[string]bool{}
	for _, w := range wb {
		want[w.text] = true
	}
	// Symbols are modelled as y or m; compared to other text, such as the
	// "" of an empty string option, the test may hold or not.
	symbols := !slices.ContainsFunc(wa, func(w cword) bool { return !tristateText(w.text) })
	var terms []*kcond.Expr
	for t := range want {
		var has []*kcond.Expr
		for _, w := range wa {
			if w.text == t {
				has = append(has, w.cond)
			}
		}
		if len(has) == 0 && symbols && !tristateText(t) {
			return atom
		}
		terms = append(terms, kcond.Or(has...))
	}
	for _, w := range wa {
		if !want[w.text] {
			terms = append(terms, kcond.Not(w.cond))
		}
	}
	return kcond.And(terms...)
}

// tristateText reports whether s is made of the letters Kconfig values
// glue to, as $(CONFIG_A)$(CONFIG_B) gives yy or ym.
func tristateText(s string) bool { return s != "" && strings.Trim(s, "ymn") == "" }

// abbreviate cuts s to n bytes.
func abbreviate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func joinWords(ws []cword) string {
	var parts []string
	for _, w := range ws {
		parts = append(parts, w.text)
	}
	return strings.Join(parts, " ")
}
