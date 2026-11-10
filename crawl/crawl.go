// Package crawl finds the Kbuild conditions and the architectures of
// files at the revisions of a git tree: each revision is crawled once for
// all the files that need it, and a file a revision lacks is looked up at
// its next one.
package crawl

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"slices"
	"sync"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
	"github.com/corefense-security/kcond/gitfs"
	"github.com/corefense-security/kcond/kbuild"
)

// File is a changed file to look up.
type File struct {
	Path   string
	Header bool
	Region *kcond.Expr // the condition of the changed lines
	Revs   []string    // the revisions to read the Makefiles from, in order
}

// Result is what the crawl found for a file.
type Result struct {
	// Rev is the revision whose Makefiles were read: the first of the
	// file's Revs that has it, or "" when none does.
	Rev string
	// Cond is the file's condition in the primary build. A header whose
	// includers are not known has the status header, one of another arch
	// is not built, and a source no revision has is missing.
	Cond builds.FileCond
	// Builds holds the file's conditions in the builds other than the
	// primary one at Rev, by name.
	Builds map[string]builds.FileCond
	Arches builds.FileArches
}

// Options tune a Resolve.
type Options struct {
	Workers  int               // revisions crawled at once; 4 when 0
	Progress func(crawled int) // called after each revision crawled, with the count so far
	// Build, one of builds.ConfigBuilds, is the only build read, and the
	// architectures are left out; every build is read when it is "".
	Build string
}

const defaultWorkers = 4

// initial is what is known of a file before any revision is read.
func initial(f *File) Result {
	r := Result{Cond: builds.FileCond{Header: f.Header, Region: f.Region}, Arches: builds.FileArches{Path: f.Path, Header: f.Header}}
	if f.Header {
		r.Cond.Status = builds.StatusHeader
		if pa := builds.PathArch(f.Path); pa != "" && pa != builds.Primary {
			r.Cond.Status = builds.StatusNotBuilt
		}
	}
	return r
}

// Resolve fills in the Kbuild condition and the architectures of every
// file at the first of its revisions that has it, crawling each revision
// once for all the files that need it. A header is never missing: without
// a revision that has it, it keeps the status header. The results are in
// the order of files.
func Resolve(ctx context.Context, dir string, files []*File, opts Options) ([]Result, error) {
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	results := make([]Result, len(files))
	next := make([]int, len(files))
	var pending []int
	for i, f := range files {
		results[i] = initial(f)
		if len(f.Revs) > 0 {
			pending = append(pending, i)
		} else if !f.Header {
			results[i].Cond.Status = builds.StatusMissing
		}
	}
	crawled := 0
	for len(pending) > 0 {
		byRev := map[string][]int{}
		for _, i := range pending {
			rev := files[i].Revs[next[i]]
			byRev[rev] = append(byRev[rev], i)
		}
		pending = pending[:0]
		revs := slices.Sorted(maps.Keys(byRev))
		// Revisions are crawled in parallel; each owns its files. The
		// first error ends the others.
		found := make([][]Result, len(revs))
		cctx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var firstErr error
		sem := make(chan struct{}, workers)
		for i, rev := range revs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if cctx.Err() != nil {
					return
				}
				in := make([]*File, len(byRev[rev]))
				for j, k := range byRev[rev] {
					in[j] = files[k]
				}
				res, err := Rev(cctx, dir, rev, in, opts.Build)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					return
				}
				found[i] = res
				crawled++
				if opts.Progress != nil {
					opts.Progress(crawled)
				}
			}()
		}
		wg.Wait()
		cancel()
		if firstErr != nil {
			return nil, firstErr
		}
		for ri, rev := range revs {
			for fi, i := range byRev[rev] {
				if found[ri] != nil && found[ri][fi].Rev != "" {
					results[i] = found[ri][fi]
					continue
				}
				if next[i]++; next[i] < len(files[i].Revs) {
					pending = append(pending, i)
				} else if !files[i].Header {
					results[i].Cond.Status = builds.StatusMissing
				}
			}
		}
	}
	return results, nil
}

// Rev computes the conditions and architectures at rev of the files that
// exist there, in the order of files; a file rev lacks has an empty
// result; build is Options.Build. A revision the tree does not have, or
// without a top-level Makefile, has no files.
func Rev(ctx context.Context, dir, rev string, files []*File, build string) ([]Result, error) {
	tree, err := gitfs.Open(ctx, dir, rev)
	if err != nil {
		var gerr *gitfs.Error
		if errors.As(err, &gerr) {
			return nil, nil // e.g. the parent of a root commit
		}
		return nil, err
	}
	defer tree.Close()
	results := make([]Result, len(files))
	var found []int
	for i, f := range files {
		if _, err := fs.Stat(tree, f.Path); err == nil {
			results[i] = initial(f)
			results[i].Rev = rev
			found = append(found, i)
		}
	}
	if len(found) == 0 {
		return results, nil
	}
	// add records what build b says of the files, and with arches of
	// their architectures.
	add := func(b builds.Build, arches bool) error {
		for _, i := range found {
			f, r := files[i], &results[i]
			fc := builds.BuildCond(f.Path, f.Header, f.Region, b)
			if arches {
				r.Arches.Add(b, f.Region)
			}
			if !b.X86_64 {
				if r.Builds == nil {
					r.Builds = map[string]builds.FileCond{}
				}
				r.Builds[b.Name] = fc
				continue
			}
			r.Cond = fc
		}
		return ctx.Err()
	}
	var paths []string
	for _, i := range found {
		paths = append(paths, files[i].Path)
	}
	if build != "" {
		b, ok := builds.Named(tree, build, paths)
		switch {
		case errors.Is(b.Err, kbuild.ErrNoMakefile):
			return nil, nil
		case !ok:
			return results, nil // the revision lacks the build
		case b.Kbuild == nil:
			return nil, b.Err // e.g. the #include scan failed
		}
		return results, add(b, false)
	}
	res, err := kbuild.Crawl(tree, kbuild.Options{Arch: builds.Primary, Lookups: paths})
	if errors.Is(err, kbuild.ErrNoMakefile) {
		return nil, nil
	}
	if err != nil {
		return nil, err // e.g. the #include scan failed
	}
	err = builds.Each(tree, res, nil, func(b builds.Build) error { return add(b, true) })
	return results, err
}
