package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/restic/restic/internal/data"
	"github.com/restic/restic/internal/errors"
	"github.com/restic/restic/internal/global"
	"github.com/restic/restic/internal/restic"
	"github.com/restic/restic/internal/ui"
	"github.com/restic/restic/internal/ui/progress"
	"github.com/restic/restic/internal/walker"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type HashOptions struct {
	Sha512        bool
	Sha256        bool
	Sha1          bool
	Md5           bool
	Sha3_224      bool
	Sha3_256      bool
	Sha3_384      bool
	Sha3_512      bool
	NullSep       bool
	TaggedFmt     bool
	PrefixAlgoFmt bool
	data.SnapshotFilter
}

type BlobHashers struct {
	name   string
	hasher hash.Hash
}

func newHashCommand(globalOptions *global.Options) *cobra.Command {
	var opts HashOptions

	cmd := &cobra.Command{
		Use:   "hash [flags] snapshotID",
		Short: "Print cksum(1)-like hashes of files contained in a snapshot to stdout",
		Long: `
The "hash" command computes and prints hashes of files contained in a given
snapshot, much like sha256sum(1) or cksum(1) would when iterating over files in
a directory tree.

Selection of at least one available hash algorithm is required.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
`,
		DisableAutoGenTag: true,
		GroupID:           cmdGroupDefault,
		RunE: func(cmd *cobra.Command, args []string) error {
			finalizeSnapshotFilter(&opts.SnapshotFilter)
			return runHash(cmd.Context(), opts, *globalOptions, args, globalOptions.Term)
		},
	}
	opts.AddFlags(cmd.Flags())
	return cmd
}

func (opts *HashOptions) AddFlags(f *pflag.FlagSet) {
	f.BoolVarP(&opts.Sha3_224, "sha3-224", "", false, `calculate and print SHA-3 224 bit hashes`)
	f.BoolVarP(&opts.Sha3_256, "sha3-256", "3", false, `calculate and print SHA-3 256 bit hashes`)
	f.BoolVarP(&opts.Sha3_384, "sha3-384", "", false, `calculate and print SHA-3 384 bit hashes`)
	f.BoolVarP(&opts.Sha3_512, "sha3-512", "", false, `calculate and print SHA-3 512 bit hashes`)
	f.BoolVarP(&opts.Sha512, "sha512", "5", false, `calculate and print SHA-2 512 bit hashes`)
	f.BoolVarP(&opts.Sha256, "sha256", "2", false, `calculate and print SHA-2 256 bit hashes`)
	f.BoolVarP(&opts.Sha1, "sha1", "1", false, `calculate and print SHA-1 (Secure Hash Algorithm 1) 160 bit hashes`)
	f.BoolVarP(&opts.Md5, "md5", "m", false, `calculate and print MD5 (Message Digest) 128 bit hashes`)
	f.BoolVarP(&opts.NullSep, "zero", "z", false, `end each output line with NUL, not newline, and disable file name escaping`)
	f.BoolVarP(&opts.TaggedFmt, "output-tagged", "", false, `use cksum(1)-like "tagged", unescaped output format`)
	f.BoolVarP(&opts.PrefixAlgoFmt, "output-prefix-algo", "", false, `prefix each output line with algorithm name (non-standard)`)
	initSingleSnapshotFilter(f, &opts.SnapshotFilter)
}

func setupHashers(opts HashOptions) []BlobHashers {
	var hs []BlobHashers

	if opts.Sha3_224 {
		hs = append(hs, BlobHashers{"SHA3-224", sha3.New224()})
	}
	if opts.Sha3_256 {
		hs = append(hs, BlobHashers{"SHA3-256", sha3.New256()})
	}
	if opts.Sha3_384 {
		hs = append(hs, BlobHashers{"SHA3-384", sha512.New384()})
	}
	if opts.Sha3_512 {
		hs = append(hs, BlobHashers{"SHA3-512", sha3.New512()})
	}
	if opts.Sha512 {
		hs = append(hs, BlobHashers{"SHA512", sha512.New()})
	}
	if opts.Sha256 {
		hs = append(hs, BlobHashers{"SHA256", sha256.New()})
	}
	if opts.Sha1 {
		hs = append(hs, BlobHashers{"SHA1", sha1.New()})
	}
	if opts.Md5 {
		hs = append(hs, BlobHashers{"MD5", md5.New()})
	}

	return hs
}

func setupMultiWriter(hs []BlobHashers) io.Writer {
	writers := make([]io.Writer, len(hs))
	for i := range hs {
		writers[i] = hs[i].hasher
	}
	return io.MultiWriter(writers...)
}

func runHash(ctx context.Context, opts HashOptions, gopts global.Options, args []string, term ui.Terminal) error {
	if len(args) != 1 {
		return errors.Fatal("no snapshot ID specified")
	}

	if opts.TaggedFmt && opts.NullSep {
		return errors.Fatal("tagged output and NUL-terminated records are mutually exclusive")
	}

	if opts.TaggedFmt && opts.PrefixAlgoFmt {
		return errors.Fatal("tagged output and algorithm-prefixed output are mutually exclusive")
	}

	if !(opts.Sha3_224 || opts.Sha3_256 || opts.Sha3_384 || opts.Sha3_512 || opts.Sha512 || opts.Sha256 || opts.Sha1 || opts.Md5) {
		return errors.Fatal("using at least one hash algorithm is mandatory")
	}

	printer := progress.NewTerminalPrinter(false, gopts.Verbosity, term)

	snapshotIDString := args[0]

	ctx, repo, unlock, err := openWithReadLock(ctx, gopts, gopts.NoLock, printer)
	if err != nil {
		return err
	}
	defer unlock()

	sn, subfolder, err := opts.SnapshotFilter.FindLatest(ctx, repo, repo, snapshotIDString)
	if err != nil {
		return errors.Fatalf("failed to find snapshot: %v", err)
	}

	err = repo.LoadIndex(ctx, printer)
	if err != nil {
		return err
	}

	sn.Tree, err = data.FindTreeDirectory(ctx, repo, sn.Tree, subfolder)
	if err != nil {
		return err
	}

	err = walker.Walk(ctx, repo, *sn.Tree, walker.WalkVisitor{
		ProcessNode: func(parent restic.ID, path string, node *data.Node, nodeErr error) error {
			escapedPath := false
			recsep := "\n"
			if opts.NullSep {
				recsep = "\x00"
			}
			if nodeErr != nil {
				return nodeErr
			}

			if node == nil {
				return nil
			}

			if node.Type == "file" {
				hashers := setupHashers(opts)
				mw := setupMultiWriter(hashers)

				for _, blobID := range node.Content {
					blobdata, err := repo.LoadBlob(ctx, restic.BlobHandle{Type: restic.DataBlob, ID: blobID}, nil)
					if err != nil {
						return err
					}
					mw.Write(blobdata)
				}
				if strings.Contains(path, "\\") {
					path = strings.ReplaceAll(path, "\\", "\\\\")
					escapedPath = true
				}
				if strings.Contains(path, "\n") {
					path = strings.ReplaceAll(path, "\n", "\\n")
					escapedPath = true
				}
				algoPrefix := ""
				if opts.TaggedFmt {
					for _, h := range hashers {
						fmt.Printf("%s (.%s) = %x\n", h.name, path, h.hasher.Sum(nil))
					}
				} else if !opts.NullSep && escapedPath {
					for _, h := range hashers {
						if opts.PrefixAlgoFmt {
							algoPrefix = fmt.Sprintf("%9s ", h.name)
						}
						fmt.Printf("%s\\%x  .%s%s", algoPrefix, h.hasher.Sum(nil), path, recsep)
					}
				} else {
					for _, h := range hashers {
						if opts.PrefixAlgoFmt {
							algoPrefix = fmt.Sprintf("%9s ", h.name)
						}
						fmt.Printf("%s%x  .%s%s", algoPrefix, h.hasher.Sum(nil), path, recsep)
					}
				}
			}
			return nil
		},
	})

	return nil
}
