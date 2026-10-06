# libmkiso fuzzing

This standalone Rust 2024 package follows the honggfuzz layout in
`../ms-compress` and Task conventions in `../windows-uup`. Its separate
manifest/lockfile keeps fuzz dependencies out of production builds. The richer
UDF harness was adapted from `../archive-rs/fuzz`, which windows-uup re-exports;
its MIT notice is retained in [LICENSE.archive-rs](LICENSE.archive-rs).
The fuzz package enables the library's `cli` feature for manifest coverage;
`progress` remains covered by the main repository's feature-matrix tests.

| Target | Input and checks |
| --- | --- |
| `iso9660` | Complete image bytes; all five primary/Joliet/Rock Ridge namespace selections, traversal, bounded extraction and invalid indices |
| `udf` | Complete image bytes, parsed unchanged and with bounded descriptor CRC/checksum repair; streaming vs allocating extraction, stream counting, output failures, size limits and invalid indices |
| `bridge` | Complete legacy ISO/UDF bridge image; both portable parsers |
| `roundtrip` | One selector byte plus up to 32 KiB payload; ISO, UDF and legacy bridge writer/reader consistency. The legacy bridge has an empty ISO root and stores files in UDF |
| `iso_roundtrip` | 16-byte configuration header plus up to 32 KiB payload; ISO levels 1–3, strict/mangled names, Joliet levels 1–3, Unicode/long/colliding aliases, Rock Ridge ownership and links, real level-3 extents, BIOS/EFI catalogs, all boot emulations, boot-info/GRUB patches, MBR/GPT/hybrid layouts, cancellation, progress failures, determinism, resource limits and overwrite preservation |
| `udf_roundtrip` | 16-byte configuration header plus payload, at most 64 KiB total; all six revisions, seven partition variants, four allocation modes, ICB strategies, file-set chains, allocation continuations, streams, links, sparse/allocated holes, preallocation, sparing remaps, fragmentation, boot images, hashes, determinism, budgets, invalid names, cancellation and overwrite preservation |
| `media` | At most 64 KiB of TOML; single-image/multiboot schema loading and validation, JSON identity, source-relative path and timestamp validation. Does not follow manifest paths or execute media/device operations |

ISO parser inputs are capped at 8 MiB, metadata at 1 MiB, entries at 128,
nesting at 16 and total streaming output per namespace at 32 KiB. UDF input is
capped at 4 MiB, metadata at 2 MiB, entries at 512, nesting at 16, individual
files at 1 MiB and total file sizes at 2 MiB. UDF extraction hashes output rather
than retaining large payloads; allocating reads have a 16 KiB budget. Structured
writers cap image sizes and payloads before authoring. Panics are not caught;
malformed image errors are expected. CRC repair preserves structural fields
and is performed only after parsing the unmodified input, retaining integrity
rejection coverage while reaching deeper mutated descriptors.

`task fuzz:seed` generates complete valid images and matching writer recipes,
plus rejection/cancellation recipes. Rich seeds span ISO options and UDF revision/
partition/allocation combinations. Dedicated UDF seeds exercise fragmented
metadata, recovery from damaged primary metadata via its mirror, and metadata
allocation descriptor chains. Smoke tests assert actual payload/stream extraction,
links, multiple extents and boot/hybrid paths, so silently rejected valid seeds
fail validation. Unix hosts additionally exercise host hard links and symlinks,
including long Rock Ridge continuation areas. Windows skips those Unix host
operations; portable UDF links remain exercised.

Generated images and roundtrips are consistency oracles, not independent format
oracles. This does not cover every option combination or establish a source
coverage percentage. Remaining separate gates include large-file behavior,
firmware boot, Windows installation, terminal rendering, external Ventoy assets,
media orchestration and device provisioning. Existing independent-reader and
repository feature-matrix tests remain necessary.

Use Linux or WSL for instrumented campaigns. Enter `nix develop` for native
honggfuzz prerequisites and install the matching CLI if needed:

```sh
cargo install honggfuzz --version 0.5.62 --locked
nix develop
task fuzz:check
task fuzz:seed
HFUZZ_RUN_ARGS="-n 1 -t 5 -N 10000 --exit_upon_crash" task fuzz -- iso9660
HFUZZ_RUN_ARGS="-n 1 -t 5 -N 10000 --exit_upon_crash" task fuzz -- udf
HFUZZ_RUN_ARGS="-n 1 -t 5 -N 10000 --exit_upon_crash" task fuzz -- iso_roundtrip
HFUZZ_RUN_ARGS="-n 1 -t 5 -N 10000 --exit_upon_crash" task fuzz -- udf_roundtrip
```

Run all seven bounded campaigns, saving tool versions, input/source hashes,
per-target logs, crash workspaces and a checked JSON summary:

```sh
nix develop -c python3 scripts/fuzz-smoke.py --iterations 10000
# Or select particular targets:
nix develop -c python3 scripts/fuzz-smoke.py --iterations 10000 udf iso_roundtrip
```

Evidence is retained under a fresh `target/fuzz-runs/<UTC timestamp>-<pid>/`.
The runner requires zero crashes/timeouts and at least the requested iterations,
even if honggfuzz exits zero after a finding. It applies per-target input caps,
one worker and a five-second input timeout. Preserve findings and logs before
rerunning; promote fixed findings into descriptive checked-in regression fixtures.

Remove `-N` from a direct Task command for continuous fuzzing. Task uses absolute
build/workspace paths under `target/`, disables the compiler wrapper and incremental
compilation, selects GCC and disables Nix hardening for instrumentation. Corpora
and crash workspaces are ignored. CI runs formatting, Clippy and smoke tests,
not instrumented campaigns.

Without Task, run checks and generate seeds from the repository root:

```sh
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path fuzz/Cargo.toml --locked
cargo run --manifest-path fuzz/Cargo.toml --locked --bin seed-images -- fuzz/corpus
export CARGO_TARGET_DIR="$PWD/target/honggfuzz-gcc"
export HFUZZ_WORKSPACE="$PWD/target/hfuzz_workspace"
cd fuzz
export RUSTC_WRAPPER="" CARGO_INCREMENTAL=0 CC=gcc NIX_HARDENING_ENABLE=""
export HFUZZ_BUILD_ARGS="--locked"
HFUZZ_INPUT=corpus/udf HFUZZ_RUN_ARGS="-n 1 -t 5 -N 10000 --exit_upon_crash" cargo hfuzz run udf
```

Replay without instrumentation:

```sh
cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- udf path/to/crash.fuzz
cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- iso_roundtrip path/to/crash.fuzz
```

On 2026-10-06, local GCC instrumented smoke campaigns completed 1,001 reported
iterations for each target with zero reported crashes or timeouts, using the
commands above. Reported runtimes were 1 s for ISO9660, 1 s for UDF and 10 s for
roundtrip. Logs are retained locally under `target/fuzz-validation-20261006/`;
the workspace is under `target/hfuzz_workspace/`. These short runs are not
sustained fuzzing or firmware/installation validation. Formatting, Clippy,
harness tests, seed generation and uninstrumented replay also passed. CI has
not run as part of this local validation. The initial Clang build failed to
link BlocksRuntime; retrying GCC in a fresh build directory succeeded.
