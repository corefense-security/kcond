# kcond

kcond answers under which CONFIG_ options the Linux kernel compiles a
file, some of its lines or a change: it evaluates the Kbuild Makefiles
of each architecture build symbolically, reads the `#if` and
`IS_ENABLED()` regions around lines, reads the Kconfig tree to tell which
values a symbol can take, and evaluates the conditions against a
`.config`. It is a Go library with a command line and depends on the
standard library and git (2.31 or later) only.

## Install

    go install github.com/corefense-security/kcond/cmd/kcond@latest

Or `make build` in a checkout, for `bin/kcond`.

## The tree

A command reads the kernel tree the current directory is in, found the
way git finds a repository, or the one `--tree DIR` names: as checked
out, or at a git revision with `--rev REV`, through git's object store,
so the checkout stays as it is. A checkout is grepped with ripgrep when
it is installed, several times faster than git grep. Paths are relative to the current
directory, or to the tree with `--tree`, and name files of the tree. The builds are x86_64, i386,
arm64, arm, powerpc, s390, riscv and loongarch; `--build NAME` reads one
of them, `--config FILE` the one the `.config` is for, and otherwise
every build the tree has. One build of a recent tree takes about a
second to read. Flags may come before or after the command.

## Questions

`cond` gives the condition under which each build compiles a file, or
some of its lines: the Kbuild condition of the file, the `#if` region of
the lines and their AND; with `--config`, whether that holds for the
`.config`:

    $ kcond cond net/ipv4/tcp_ipv4.c:90 net/ipv4/tcp_ipv4.c --rev v6.12 --config .config
    net/ipv4/tcp_ipv4.c:90	x86_64	built	CONFIG_INET && CONFIG_NET	CONFIG_TCP_MD5SIG	CONFIG_INET && CONFIG_NET && CONFIG_TCP_MD5SIG	applies
    net/ipv4/tcp_ipv4.c	x86_64	built	CONFIG_INET && CONFIG_NET	true	CONFIG_INET && CONFIG_NET	applies

A file is `built` under its condition, `unlisted` when no Makefile names
it, and `not built` when it belongs to another architecture. A header is
`built` where the files that include it are, directly or through other
headers, each under the condition of its `#include` line: a quoted name
next to the including file, `<name>` through the build's include
directories and the `asm-generic` headers the `generic-y` and
`mandatory-y` lists stand in for, and the headers `-include` flags name;
a file no Makefile names adds nothing. A header no listed file includes,
as a uapi header only userspace reads, or one only generated sources,
linker scripts or boot code read, is a `header`, whose condition is its
region when that names a `CONFIG_` option and unknown otherwise. An OR
drops an option Kconfig lets on only with another of its terms:
`CONFIG_JFFS2_FS || CONFIG_MTD` is `CONFIG_MTD`, as JFFS2 depends on MTD.

An object `obj-y` lists is linked only where its directory is entered
through `obj-y` too, so under `obj-$(CONFIG_X) += dir/` it needs
`CONFIG_X=y`, while a module is built wherever its directory is entered. A
condition shows that gate, as `CONFIG_X=y && CONFIG_Y` for a bool `Y` or
`(CONFIG_X=y || CONFIG_Y=m)` for a tristate, unless Kconfig settles it: a
tristate `Y` that depends on or selects `X` is `y` only with `X=y`.

`diff` reads commits, or the commits of a range such as a stable update:
the kernel files each one changes, the `#if` region (`#[cfg]` in Rust)
of the changed lines, each file's condition at the commit and the condition of the
whole change; with `--config`, whether the change applies to that
`.config`. `--build`, or `--config` for the build it is for, reads that
one build; without them every build is read, the condition is x86_64's,
and the architectures that may build the change are listed. The commit
line carries the verdict with `--config`, the arch label without it, and
the condition; the file rows follow indented, so `grep -v '^ '` is the
one-line view:

    $ kcond diff 8eb36164d1a6
    8eb36164d1a6	generic	CONFIG_BONDING || (CONFIG_CHELSIO_T4 && CONFIG_ETHERNET && CONFIG_NET_VENDOR_CHELSIO) || ... || CONFIG_INFINIBAND
      drivers/net/bonding/bond_main.c	built	CONFIG_BONDING	region true	arches x86,arm64,arm,powerpc,s390,riscv,loongarch
      drivers/net/bonding/bond_options.c	built	CONFIG_BONDING	region true	arches x86,arm64,arm,powerpc,s390,riscv,loongarch
      include/net/bond_options.h	built	CONFIG_BONDING || (CONFIG_CHELSIO_T4 && CONFIG_ETHERNET && CONFIG_NET_VENDOR_CHELSIO) || ... || CONFIG_INFINIBAND	region true	arches x86,arm64,arm,powerpc,s390,riscv,loongarch
    $ kcond diff v6.12.1..v6.12.2 --config .config | grep -v '^ ' | grep -w applies
    78de864e8af3649b03f905e206e6f06f3aa4c006	applies	true
    cfe3e04e9a5704aac92aaa2b45706850d96af0b9	applies	true
    26cc5063e3c2a5d14f42fe623c9567bd1499fb19	applies	CONFIG_EXT4_FS
    ...

A range lists its commits oldest first and reads the Makefiles at its
end; the 815 commits of v6.12.1..v6.12.2 take about 10 seconds with
`--config` and 40 reading every build, the public headers they change
looked up in each. A merge in a range reads as its
own change, the hunks that differ from every parent, as `git show`
prints them, so a clean merge reads `none`; a merge named alone reads as
its diff to its first parent, everything it brings. A commit that
changes only what the build never reads, documentation,
selftests, perf or comments, does not apply, with the label `none` and
the condition `false`; one that changes no kernel code but Makefiles,
Kconfig or device trees has no label and is unknown.

`arches` lists the architectures that may build a file, those where its
condition is unknown and those that always build it, and labels the set
`generic`, `several`, one architecture, `other` or `none`:

    $ kcond arches drivers/net/bonding/bond_main.c arch/arm64/kernel/smccc-call.S --rev v6.12
    drivers/net/bonding/bond_main.c	arches x86,arm64,arm,powerpc,s390,riscv,loongarch	unknown 	always 
    arch/arm64/kernel/smccc-call.S	arches arm64	unknown 	always arm64
    label: generic

`files` lists the sources one build compiles under the given
directories, the current one by default, with their Kbuild conditions; with `--config`, only those
the `.config` builds, for scoping a static analysis or a coverage run:

    $ kcond files drivers/net/bonding --rev v6.12
    drivers/net/bonding/bond_3ad.c	CONFIG_BONDING
    drivers/net/bonding/bond_alb.c	CONFIG_BONDING
    drivers/net/bonding/bond_debugfs.c	CONFIG_BONDING
    drivers/net/bonding/bond_main.c	CONFIG_BONDING
    drivers/net/bonding/bond_netlink.c	CONFIG_BONDING
    drivers/net/bonding/bond_options.c	CONFIG_BONDING
    drivers/net/bonding/bond_procfs.c	CONFIG_BONDING && CONFIG_PROC_FS
    drivers/net/bonding/bond_sysfs.c	CONFIG_BONDING
    drivers/net/bonding/bond_sysfs_slave.c	CONFIG_BONDING
    $ kcond files net/ipv4 --rev v6.12 --config .config | wc -l
    73

`symbols` tells what a build's Kconfig says about symbols: the values
they can take (`n`, `m`, `y`), whether they can be modules and which
symbols they require, or that the Kconfig has no bool or tristate of the
name; with `--config`, what the `.config` sets them and their
requirements to:

    $ kcond symbols BONDING --rev v6.12 --config .config
    CONFIG_BONDING	x86_64	values nmy	modular true	config n	requires CONFIG_INET=y,CONFIG_NET=y,CONFIG_NETDEVICES=y,CONFIG_NET_CORE=y

`config` reads a `.config`, plain or gzip-compressed, and `eval` tells
whether conditions hold for it: a condition `applies`, is `not
applicable`, or is `unknown` when an atom no `.config` decides, such as
a macro, is left:

    $ kcond config .config
    build: x86_64
    version: 6.12.0
    partial: false
    options: 1704
    $ kcond eval CONFIG_NET CONFIG_BONDING CONFIG_NET=m '"defined(FOO)" && CONFIG_NET' --config .config
    CONFIG_NET	applies
    CONFIG_BONDING	not applicable
    CONFIG_NET=m	not applicable
    "defined(FOO)" && CONFIG_NET	unknown

Conditions are written `CONFIG_A && (CONFIG_B || !CONFIG_C)`; `CONFIG_X=y`
and `CONFIG_X=m` test one tristate value, a bare `CONFIG_X` either. An
option a `.config` does not list is off. `-q` prints nothing and makes
the exit status the answer, 0 when every condition or commit applies and
1 otherwise, so a script can ask `kcond eval -q --config .config
CONFIG_BONDING`; errors exit 2. Every command prints JSON with `--json`.

## Library

```go
import (
	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
	"github.com/corefense-security/kcond/dotconfig"
	"github.com/corefense-security/kcond/gitfs"
)

tree, err := gitfs.Open(ctx, dir, "v6.12")  // an fs.FS; gitfs.WorkTree reads a checkout
b, ok := builds.Named(tree, "x86_64")        // the Makefile crawl and the Kconfig analysis
fc := builds.BuildCond(path, false, kcond.Const(true), b) // Status, Kbuild, Region
e, err := kcond.Parse("CONFIG_A && !CONFIG_B")
f, err := dotconfig.Read(data)               // Config, Version, Build
v := e.Eval(f.Config)                        // kcond.True, False or Unknown
```

`builds.Each` walks every build of a tree; `change.Changes` reads the
files and regions a commit's diff touches, `builds.Combine` and
`builds.Summarize` turn them into one condition and an architecture
label, and `crawl.Resolve` does that for many files across revisions,
crawling each revision once. `kconfig.Parse` and `kconfig.Analyze` give
the values each symbol can take.

## Development

    make lint   # gofmt and go vet
    make test   # go test -race ./...
    make build  # bin/kcond, with the version of git describe for --version

The module depends on the standard library only; `deps_test.go` checks
it. The tests build small repositories with git;
`kbuild/testdata/kbuild/check.sh` records what the kernel's own Kbuild
makes of the test Makefiles.

## License

MIT, see LICENSE.
