package change

import (
	"testing"

	"github.com/corefense-security/kcond"
)

type blobs map[string]string

func (b blobs) Get(spec string) ([]byte, bool, error) {
	s, ok := b[spec]
	return []byte(s), ok, nil
}

const fooOld = `#include <linux/foo.h>

static int foo_setup(void)
{
	int ret = 0;
#ifdef CONFIG_FOO_DEBUG
	pr_debug("setup\n");
#endif
	if (IS_ENABLED(CONFIG_FOO_EXTRA))
		ret = foo_extra();
	return ret;
}
`

const fooNew = `#include <linux/foo.h>

static int foo_setup(void)
{
	int ret = 0;
#ifdef CONFIG_FOO_DEBUG
	pr_debug("setup %d\n", ret);
#endif
	if (IS_ENABLED(CONFIG_FOO_EXTRA))
		ret = foo_extra_checked();
	return ret;
}
`

const diff = `diff --git a/drivers/foo/foo.c b/drivers/foo/foo.c
--- a/drivers/foo/foo.c
+++ b/drivers/foo/foo.c
@@ -6,6 +6,6 @@ static int foo_setup(void)
 #ifdef CONFIG_FOO_DEBUG
-	pr_debug("setup\n");
+	pr_debug("setup %d\n", ret);
 #endif
 	if (IS_ENABLED(CONFIG_FOO_EXTRA))
-		ret = foo_extra();
+		ret = foo_extra_checked();
 	return ret;
diff --git a/drivers/foo/comment.c b/drivers/foo/comment.c
--- a/drivers/foo/comment.c
+++ b/drivers/foo/comment.c
@@ -1,2 +1,3 @@
 int x;
+/* explain x */
 int y;
diff --git a/drivers/foo/moved.c b/drivers/foo/moved.c
--- a/drivers/foo/moved.c
+++ b/drivers/foo/moved.c
@@ -1,2 +1,3 @@
-int a; /* a */
+/* a */
+int a;
 int b;
diff --git a/drivers/foo/reorder.c b/drivers/foo/reorder.c
--- a/drivers/foo/reorder.c
+++ b/drivers/foo/reorder.c
@@ -1,2 +1,2 @@
+int b;
 int a;
-int b;
diff --git a/Documentation/foo.rst b/Documentation/foo.rst
--- a/Documentation/foo.rst
+++ b/Documentation/foo.rst
@@ -1 +1 @@
-old
+new
diff --git a/include/linux/foo.h b/include/linux/foo.h
--- a/include/linux/foo.h
+++ b/include/linux/foo.h
@@ -1,3 +1,3 @@
 #ifdef CONFIG_FOO
-int foo(void);
+int foo(int);
 #endif
`

func TestChanges(t *testing.T) {
	b := blobs{
		"h^:drivers/foo/foo.c":     fooOld,
		"h:drivers/foo/foo.c":      fooNew,
		"h:drivers/foo/comment.c":  "int x;\n/* explain x */\nint y;\n",
		"h^:drivers/foo/moved.c":   "int a; /* a */\nint b;\n",
		"h:drivers/foo/moved.c":    "/* a */\nint a;\nint b;\n",
		"h^:drivers/foo/reorder.c": "int a;\nint b;\n",
		"h:drivers/foo/reorder.c":  "int b;\nint a;\n",
		"h^:include/linux/foo.h":   "#ifdef CONFIG_FOO\nint foo(void);\n#endif\n",
		"h:include/linux/foo.h":    "#ifdef CONFIG_FOO\nint foo(int);\n#endif\n",
	}
	got := Changes(b, "h", diff)
	if len(got) != 5 {
		t.Fatalf("Changes = %+v, want foo.c, comment.c, moved.c, reorder.c and foo.h", got)
	}
	foo := got[0]
	if foo.Path != "drivers/foo/foo.c" || foo.Header || !foo.Code ||
		foo.Region.String() != "CONFIG_FOO_DEBUG=y || CONFIG_FOO_EXTRA" ||
		len(foo.Functions) != 1 || foo.Functions[0] != "static int foo_setup(void)" {
		t.Errorf("foo.c = %+v (region %s)", foo, foo.Region)
	}
	if c := got[1]; c.Path != "drivers/foo/comment.c" || c.Code {
		t.Errorf("comment.c = %+v, want no code change", c)
	}
	if c := got[2]; c.Path != "drivers/foo/moved.c" || c.Code || c.Region.String() != "false" {
		t.Errorf("moved.c = %+v, want no code change", c)
	}
	// A line moved past other code is a code change.
	if c := got[3]; c.Path != "drivers/foo/reorder.c" || !c.Code || c.Region.String() != "true" {
		t.Errorf("reorder.c = %+v, want a code change", c)
	}
	if h := got[4]; h.Path != "include/linux/foo.h" || !h.Header || h.Region.String() != "CONFIG_FOO=y" {
		t.Errorf("foo.h = %+v", h)
	}
}

// A merge's combined diff reads each parent's lines in that parent: the
// second parent's line the merge drops is read in h^2, and h^, which
// loses no line, is not read.
func TestChangesMerge(t *testing.T) {
	b := blobs{
		"h^2:m.c": "#ifdef CONFIG_X\nint x;\nint x2;\n#endif\n#ifdef CONFIG_Y\n#endif\n",
		"h:m.c":   "#ifdef CONFIG_X\nint x;\n#endif\n#ifdef CONFIG_Y\nint y;\n#endif\n",
	}
	d := "diff --cc m.c\n--- a/m.c\n+++ b/m.c\n@@@ -1,5 -1,6 +1,6 @@@\n" +
		"  #ifdef CONFIG_X\n  int x;\n -int x2;\n  #endif\n  #ifdef CONFIG_Y\n++int y;\n  #endif\n"
	got := Changes(b, "h", d)
	if len(got) != 1 || !got[0].Code || got[0].Region.String() != "CONFIG_X=y || CONFIG_Y=y" {
		t.Errorf("Changes = %+v, want m.c in CONFIG_X=y || CONFIG_Y=y", got)
	}
}

// Arch macros follow the Kconfig symbols in a source only the kernel
// compiles; in a header, which the 32-bit vDSO of an x86-64 kernel also
// includes, the line may be compiled as i386 code there.
func TestChangesArchMacros(t *testing.T) {
	b := blobs{}
	var d string
	for _, f := range []string{"kernel/signal.c", "arch/x86/include/asm/pvclock.h"} {
		b["h^:"+f] = "#ifdef __i386__\nint a;\n#endif\n"
		b["h:"+f] = "#ifdef __i386__\nint b;\n#endif\n"
		d += "diff --git a/" + f + " b/" + f + "\n--- a/" + f + "\n+++ b/" + f +
			"\n@@ -1,3 +1,3 @@\n #ifdef __i386__\n-int a;\n+int b;\n #endif\n"
	}
	got := Changes(b, "h", d)
	if len(got) != 2 {
		t.Fatalf("Changes = %+v, want signal.c and pvclock.h", got)
	}
	if r := got[0].Region.String(); r != "CONFIG_X86_32" {
		t.Errorf("signal.c region = %s, want CONFIG_X86_32", r)
	}
	if r, want := got[1].Region.String(), `("defined(__i386__)" && CONFIG_X86_64) || CONFIG_X86_32`; r != want {
		t.Errorf("pvclock.h region = %s, want %s", r, want)
	}
}

func TestChangesMissingImage(t *testing.T) {
	// Without the images the region is unknown (true), and the change
	// counts as code.
	got := Changes(blobs{}, "h", diff)
	if got[0].Region.String() != "true" || !got[0].Code {
		t.Errorf("foo.c = %+v", got[0])
	}
}

func p(t *testing.T, s string) *kcond.Expr {
	t.Helper()
	e, err := kcond.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestShort(t *testing.T) {
	requires := map[string][]string{
		"CONFIG_MPTCP":   {"CONFIG_INET", "CONFIG_NET"},
		"CONFIG_INET":    {"CONFIG_NET"},
		"CONFIG_FOO_DRV": {"CONFIG_FOO"},
		"CONFIG_LOOP_A":  {"CONFIG_LOOP_B"},
		"CONFIG_LOOP_B":  {"CONFIG_LOOP_A"},
	}
	for _, tc := range []struct{ cond, want string }{
		{"CONFIG_MPTCP && CONFIG_NET", "CONFIG_MPTCP"},
		{"CONFIG_MPTCP && CONFIG_INET && CONFIG_NET", "CONFIG_MPTCP"},
		// A =y or =m test requires as much as a plain one, but stays.
		{"CONFIG_FOO_DRV=m && CONFIG_FOO", "CONFIG_FOO_DRV=m"},
		{"CONFIG_FOO_DRV && CONFIG_FOO=y", "CONFIG_FOO=y && CONFIG_FOO_DRV"},
		{"CONFIG_FOO_DRV && !CONFIG_NET", "CONFIG_FOO_DRV && !CONFIG_NET"},
		// Each AND on its own: an OR does not require its branches.
		{"CONFIG_NET && (CONFIG_INET || CONFIG_FOO)", "(CONFIG_FOO || CONFIG_INET) && CONFIG_NET"},
		{"(CONFIG_INET && CONFIG_NET) || (CONFIG_FOO_DRV && CONFIG_FOO)", "CONFIG_FOO_DRV || CONFIG_INET"},
		{"CONFIG_LOOP_A && CONFIG_LOOP_B", "CONFIG_LOOP_B"},
		{"true", "true"},
	} {
		if got := Short(p(t, tc.cond), requires).String(); got != tc.want {
			t.Errorf("Short(%q) = %q, want %q", tc.cond, got, tc.want)
		}
	}
}

func TestVerdict(t *testing.T) {
	cfg := kcond.Config{"CONFIG_A": 'y'}
	for _, tc := range []struct {
		cond    string
		unknown bool
		want    kcond.Tri
	}{
		{"CONFIG_A", false, kcond.True},
		{"CONFIG_B", false, kcond.False},
		{"CONFIG_B", true, kcond.Unknown},
		{"CONFIG_A", true, kcond.True},
		{"", true, kcond.Unknown},
	} {
		var c *kcond.Expr
		if tc.cond != "" {
			c = p(t, tc.cond)
		}
		if got := Verdict(c, tc.unknown, cfg); got != tc.want {
			t.Errorf("Verdict(%q, %v) = %v, want %v", tc.cond, tc.unknown, got, tc.want)
		}
	}
}

func TestOutsideBuild(t *testing.T) {
	for p, want := range map[string]bool{
		"Documentation/process/howto.rst":      true,
		"LICENSES/preferred/GPL-2.0":           true,
		"tools/testing/selftests/net/Makefile": true,
		"tools/perf/builtin-top.c":             true,
		"MAINTAINERS":                          true,
		"CREDITS":                              true,
		".mailmap":                             true,
		".gitignore":                           true,
		"Documentation/Kconfig":                false, // the top Kconfig sources it
		"Kbuild":                               false,
		"lib/.gitignore":                       false,
		"tools/objtool/check.c":                false, // the build runs objtool
		"tools/include/linux/types.h":          false,
		"scripts/mod/modpost.c":                false,
		"Makefile":                             false,
		"drivers/net/bonding/bond_main.c":      false,
		"arch/arm64/boot/dts/qcom/sm8650.dtsi": false,
	} {
		if got := OutsideBuild(p); got != want {
			t.Errorf("OutsideBuild(%q) = %v, want %v", p, got, want)
		}
	}
}
