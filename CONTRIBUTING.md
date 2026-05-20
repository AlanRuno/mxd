# Contributing to MXD

Thanks for your interest. This guide covers building, testing, and submitting
changes.

## Building from source

Linux (Ubuntu 22.04 reference) — fastest path:

```bash
./install_dependencies_linux.sh
mkdir build && cd build
cmake ..
cmake --build . --parallel
```

macOS:

```bash
./install_dependencies_macos.sh
mkdir build && cd build
cmake ..
cmake --build . --parallel
```

Windows (MSYS2 + MinGW recommended):

```bash
./install_dependencies_windows.sh
mkdir build && cd build
cmake ..
cmake --build . --parallel
```

Build outputs:
- `build/lib/libmxd.so` (or `.dylib` / `.dll`) — chain core shared library
- `build/lib/mxd_node` — validator binary

## Running tests

C unit tests run from the build directory:

```bash
cmake --build . --target run-tests
```

Or invoke specific test binaries directly from `build/tests/`. Each test
exercises one subsystem (transaction codec, consensus, bridge validation, etc.).

Solidity contract tests use Hardhat:

```bash
cd contracts
npm install
npx hardhat test
```

Test vectors for cross-implementation conformance live in
`docs/standards/MXD-*-test-vectors.json`. If you modify wire formats or signing
rules, regenerate vectors via `tools/gen_test_vectors.c` and document the
change in the relevant `MXD-XX` spec.

## Code style

C:
- C11. No C++ features.
- 4-space indentation, no tabs.
- Function names: `mxd_snake_case` for public API, `static` helpers can drop the prefix.
- Headers are self-contained — every `*.h` includes everything it needs.
- No dynamic allocation in hot paths unless unavoidable; document why when used.
- Errors propagate as `int` return codes (0 = success). Out-params live in the last positional arg.
- Logging via `MXD_LOG_INFO("subsystem", "format", args)` — never raw `fprintf`.

Solidity:
- Match the existing style in `MXDBridgeV3.sol` (NatSpec on every external/public, named return values).
- Use `forge fmt` or Hardhat-default Prettier rules.
- Pin Solidity version per file.

Python:
- 4-space indent, PEP 8, type hints on public functions.

## Commit messages

```
<type>(<scope>): <subject>

<body — wrapping at ~72 chars, explaining WHY>

<optional: refs/closes/spec/etc>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `build`, `ci`, `security`.

Scope is the area touched: `consensus`, `bridge`, `transaction`, `api`,
`contracts`, `tools`, `docs`, etc.

Example:

```
fix(consensus): bridge mint replay protection in consensus validator

Add a consensus-level check in mxd_validate_bridge_mint_tx_consensus_only
that rejects any bridge_mint whose source_tx_hash is already present in
the RocksDB bridge_tx:<hash> index. Combined with the queue-side dedup
in mxd_queue_bridge_mint and the oracle-side row lock in bnb-monitor.js,
this closes the bug-class structurally.
```

The "WHY" matters more than the "WHAT" — diffs already say what changed.
Explain the constraint or incident that motivated the change.

## Pull request guidelines

1. **One concern per PR.** If you're touching consensus *and* updating a doc,
   split them. Reviewers shouldn't have to context-switch within a single review.
2. **Tests pass locally before pushing.** CI will gate on this; saving a round
   trip respects everyone's time.
3. **Touch tests when you touch code.** New logic gets a unit test; bug fixes
   get a regression test that fails on the pre-fix code.
4. **Update relevant `MXD-XX` specs** if your change affects wire format,
   signing rules, or the address/HD derivation. Code-spec drift is the #1 cause
   of long-tail bugs.
5. **No mainnet ops in PRs.** Configuration, IPs, hostnames, and operational
   procedures stay in the operator-private repository (`AlanRuno/mxdlib`).
   This public repo is the protocol, not the deployment.

## Reporting bugs

Open an issue with:
- What you did (commands, environment, commit hash)
- What you expected
- What happened
- Logs from the affected component (sanitized — no private keys, no validator
  identity material)

For security issues, see [`SECURITY.md`](SECURITY.md) — do not open public
issues for vulnerabilities.

## License

By submitting a PR you agree that your contribution will be licensed under
AGPL-3.0-only, matching the rest of the repository.
