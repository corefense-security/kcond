// Package dotconfig reads kernel .config files: their options, and the
// kernel version and the architecture build their header names.
package dotconfig

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
)

// File is a kernel .config as Read reads it.
type File struct {
	Config kcond.Config
	// Version is the kernel version the header names, as written:
	// 6.12.43+deb13, 6.18.0-rc3, 6.12. It is "" without a header.
	Version string
	// Build is the builds.ConfigBuilds name the header or the architecture
	// symbol gives, or "" when neither does.
	Build string
	// Partial is set when the file looks like a defconfig: no header and
	// few options switched off. The options a partial config leaves out
	// count as off, which understates what it builds.
	Partial bool
}

var headerRe = regexp.MustCompile(`(?m)^# Linux/(\S+) (\S+) Kernel Configuration`)

// buildSymbols are the symbols each architecture's Kconfig forces on, with
// the build they name.
var buildSymbols = [][2]string{{"CONFIG_X86_64", builds.X86_64Build}, {"CONFIG_X86_32", "i386"}, {"CONFIG_ARM64", "arm64"},
	{"CONFIG_ARM", "arm"}, {"CONFIG_PPC", "powerpc"}, {"CONFIG_S390", "s390"}, {"CONFIG_RISCV", "riscv"}, {"CONFIG_LOONGARCH", "loongarch"}}

// ArchSymbols are the symbols that tell the build of a config without a
// header.
func ArchSymbols() []string {
	out := make([]string, len(buildSymbols))
	for i, s := range buildSymbols {
		out[i] = s[0]
	}
	return out
}

// partialOff is the fewest "is not set" lines a full config has: kconfig
// writes thousands, a defconfig a dozen.
const partialOff = 100

// MaxBytes bounds the text of a .config. The largest any build makes at
// v7.3-rc6 is x86_64's allyesconfig with COMPILE_TEST, 433 KiB;
// distribution configs stay under 360 KB.
const MaxBytes = 512 << 10

// gzipMagic starts a gzip file, such as /proc/config.gz.
var gzipMagic = []byte{0x1f, 0x8b}

// ErrTooLarge refuses a config over MaxBytes, compressed or not.
var ErrTooLarge = fmt.Errorf("the file is larger than %d KiB, which no kernel .config is", MaxBytes>>10)

// ErrUnknownBuild is the error for a .config whose build neither a header
// nor an architecture symbol tells.
var ErrUnknownBuild = errors.New("cannot tell the architecture: the file has no header naming it and none of " +
	strings.Join(ArchSymbols(), ", "))

// Text returns the text of a .config: data itself, or what data holds
// when it is a gzip file, as /proc/config.gz and the configuration the
// kernel embeds with IKCONFIG are. Gzip data that does not decompress is
// an error, and so is text over MaxBytes, which no .config reaches.
func Text(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, gzipMagic) {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			data, err = io.ReadAll(io.LimitReader(zr, MaxBytes+1))
		}
		if err != nil {
			return nil, fmt.Errorf("the file looks gzip-compressed but does not decompress: %w", err)
		}
	}
	if len(data) > MaxBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

// Read reads a .config, plain or gzip-compressed: its text, as Text
// returns it, read by Parse.
func Read(data []byte) (File, error) {
	text, err := Text(data)
	if err != nil {
		return File{}, err
	}
	return Parse(text)
}

// Parse reads the text of a .config: its options, and the version and the
// architecture build its header names, the x86 header standing for x86-64
// unless CONFIG_X86_32 is set. Without a header the architecture symbol
// decides the build. Text without CONFIG_ options, binary, cut off after
// its header, or of an architecture no conditions exist for, is an error.
func Parse(data []byte) (File, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return File{}, errors.New("the file holds binary data: not a kernel .config")
	}
	cfg, err := kcond.ParseConfig(bytes.NewReader(data))
	if err != nil {
		return File{}, err
	}
	if len(cfg) == 0 {
		return File{}, errors.New("no CONFIG_ options: not a kernel .config")
	}
	f := File{Config: cfg}
	if m := headerRe.FindSubmatch(data); m != nil {
		// kconfig ends the file with a newline.
		if !bytes.HasSuffix(data, []byte("\n")) {
			return File{}, errors.New("the file ends in the middle of a line: it looks cut off, and the options after the cut would count as off")
		}
		f.Version = string(m[2])
		switch arch := string(m[1]); arch {
		case "x86", "x86_64", "i386":
			f.Build = builds.X86_64Build
			if arch == "i386" || cfg["CONFIG_X86_32"] != 0 {
				f.Build = "i386"
			}
		default:
			f.Build = arch
		}
	} else {
		f.Partial = bytes.Count(data, []byte(" is not set")) < partialOff
		for _, s := range buildSymbols {
			if cfg[s[0]] != 0 {
				f.Build = s[1]
				break
			}
		}
	}
	if f.Build != "" && !slices.Contains(builds.ConfigBuilds, f.Build) {
		return File{}, fmt.Errorf("no conditions for %s configurations; the builds are %s", f.Build, strings.Join(builds.ConfigBuilds, ", "))
	}
	return f, nil
}
