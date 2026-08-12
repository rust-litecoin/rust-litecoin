<div align="center">
  <h1>Rust Litecoin</h1>

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Litecoin, including the MimbleWimble Extension Block (MWEB).
  </p>

  <p>Forked from <a href="https://github.com/rust-bitcoin/rust-bitcoin">rust-bitcoin</a>;
    chain parameters, address formats, MWEB wire types and HogEx transaction handling are
    Litecoin-specific. The crate is published as <code>litecoin</code>; the module layout
    mirrors rust-bitcoin so wallet code already using rust-bitcoin can migrate by renaming
    its imports.
  </p>

  <p>
    <a href="https://github.com/rust-litecoin/rust-litecoin/blob/ltc/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://blog.rust-lang.org/2021/11/01/Rust-1.56.1.html"><img alt="Rustc Version 1.56.1+" src="https://img.shields.io/badge/rustc-1.56.1%2B-lightgrey.svg"/></a>
  </p>
</div>

Supports (or should support)

* De/serialization of Litecoin protocol network messages (magic bytes `0xFBC0B6DB` mainnet,
  `0xFDD2C8F1` testnet4)
* De/serialization of blocks and transactions, including MWEB extension blocks and HogEx
  bridge transactions (segwit flag bits `0x01`, `0x08`, `0x09`)
* MimbleWimble wire types — kernels, outputs, inputs, peg-in / peg-out coins, compact varints
* Script de/serialization
* Litecoin address formats — legacy P2PKH (`L…` / `m…`), P2SH (`M…` / `Q…` / `2…`), segwit
  v0–v16 bech32/bech32m with `ltc` / `tltc` / `rltc` HRPs, and MWEB stealth addresses
  (`ltcmweb` / `tmweb`)
* Private keys (WIF prefix `0xB0` mainnet / `0xEF` testnet) and BIP32 derivation
* Litecoin signed-message prefix (`\x19Litecoin Signed Message:\n`)
* PSBT v0 de/serialization and all but the Input Finalizer role; typed MWEB maps (`0x90+`)
  round-trip offsets, kernels, and input/output fields — `mw_tx` is assembled only at
  [`Psbt::extract_tx_with_mweb`], not on the unsigned transaction inside the PSBT

## Known limitations

### Consensus

This library **must not** be used for consensus code (i.e. fully validating blockchain data). It
technically supports parsing and re-serializing real Litecoin mainnet blocks (including those
containing MWEB extensions and the regression block `#2,644,351`), but full validation requires
matching Litecoin Core bit-for-bit — which this library does not attempt.

In a consensus based cryptocurrency it is critical that all parties are using the same rules
to validate data, and this library is simply unable to implement the same rules as Core. Of
course, patches to fix specific consensus incompatibilities are welcome.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported and we can't promise they will be. If you care about them
please let us know, so we can know how large the interest is and possibly decide to support them.

## Documentation

API docs follow upstream rust-bitcoin's structure under the `litecoin::*` namespace. Most
Bitcoin-named types map directly onto Litecoin equivalents; the MWEB-specific surface lives in
`litecoin::blockdata::mimblewimble` and on the `Block` / `Transaction` extension fields.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please discuss them in
an issue before PRing them to avoid duplicate work and architectural mismatches.

For more information please see `./CONTRIBUTING.md`.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.56.1**.

To build with the MSRV you will likely need to pin a bunch of dependencies, see `./contrib/test.sh`
for the current list.

## External dependencies

We integrate with a few external libraries, most notably `serde`. These
are available via feature flags. To ensure compatibility and MSRV stability we
provide two lock files as a means of inspecting compatible versions:
`Cargo-minimal.lock` containing minimal versions of dependencies and
`Cargo-recent.lock` containing recent versions of dependencies tested in our CI.

We do not provide any guarantees about the content of these lock files outside
of "our CI didn't fail with these versions". Specifically, we do not guarantee
that the committed hashes are free from malware. It is your responsibility to
review them.

## Installing Rust

Rust can be installed using your package manager of choice or [rustup.rs](https://rustup.rs). The
former way is considered more secure since it typically doesn't involve trust in the CA system. But
you should be aware that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem since we follow upstream rust-bitcoin's MSRV — much older than
the current stable Rust (see MSRV section).

## Building

The cargo feature `std` is enabled by default. At least one of the features `std` or `no-std` or
both must be enabled.

Enabling the `no-std` feature does not disable `std`. To disable the `std` feature you must disable
default features. The `no-std` feature only enables additional features required for this crate to
be usable without `std`. Both can be enabled without conflict.

The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:rust-litecoin/rust-litecoin.git
cd rust-litecoin
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more
detailed instructions.

### Just

We support [`just`](https://just.systems/man/en/) for running dev workflow commands. Run `just` from
your shell to see list available sub-commands.

### Building the docs

We build docs with the nightly toolchain, you may wish to use the following shell alias to check
your documentation changes build correctly.

```
alias build-docs='RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links'
```

## Testing

Unit and integration tests are available for those interested, along with benchmarks. For project
developers, especially new contributors looking for something to work on, we do:

- Fuzz testing with [`Hongfuzz`](https://github.com/rust-fuzz/honggfuzz-rs)
- Mutation testing with [`Mutagen`](https://github.com/llogiq/mutagen)
- Code verification with [`Kani`](https://github.com/model-checking/kani)

There are always more tests to write and more bugs to find, contributions to our testing efforts
extremely welcomed. Please consider testing code a first class citizen, we definitely do take PRs
improving and cleaning up test code.

### Unit/Integration tests

Run as for any other Rust project `cargo test --all-features`.

### Benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.

### Mutation tests

We have started doing mutation testing with [mutagen](https://github.com/llogiq/mutagen). To run
these tests first install the latest dev version with `cargo +nightly install --git https://github.com/llogiq/mutagen`
then run with `RUSTFLAGS='--cfg=mutate' cargo +nightly mutagen`.

### Code verification

We have started using [kani](https://github.com/model-checking/kani), install with `cargo install --locked kani-verifier`
 (no need to run `cargo kani setup`). Run the tests with `cargo kani`.

## Pull Requests

Every PR needs at least two reviews to get merged. During the review phase maintainers and
contributors are likely to leave comments and request changes. Please try to address them, otherwise
your PR might get closed without merging after a longer time of inactivity. If your PR isn't ready
for review yet please mark it by prefixing the title with `WIP: `.

### CI Pipeline

The CI pipeline requires approval before being run on each MR.

In order to speed up the review process the CI pipeline can be run locally using
[act](https://github.com/nektos/act). The `fuzz` and `Cross` jobs will be skipped when using `act`
due to caching being unsupported at this time. We do not *actively* support `act` but will merge PRs
fixing `act` issues.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

## Relationship to upstream rust-bitcoin

This is a fork. We pull from `rust-bitcoin/rust-bitcoin` periodically and re-apply the
Litecoin-specific layer on top — chain identity, MWEB wire types, HogEx handling, LTC address
HRPs, magic bytes, genesis, WIF prefix, signed-message prefix. The main crate is published as
`litecoin`; subsidiary crates (`bitcoin_hashes`, `bitcoin-internals`, `bitcoin-io`,
`bitcoin-units`, `base58ck`) keep their upstream names since they are shared crypto utilities.

Bug reports about the Litecoin layer belong here; bug reports about Bitcoin-shared code should
generally be filed upstream first.


## Release Notes

Release notes are done per crate, see:

- [litecoin CHANGELOG](litecoin/CHANGELOG.md)
- [hashes CHANGELOG](hashes/CHANGELOG.md)
- [internals CHANGELOG](internals/CHANGELOG.md)


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
