# CLOB with Onchain State Verification.

This repo implements an offchain orderbook (CLOB) that produces an SP1 proof for each batch of
matching and state transition; the onchain verifier accepts the new canonical state root only if
the proof verifies.

## Repo layout

- `crates/core`: shared serialization, keccak hashing, sparse Merkle map, matching engine, rounding, state model
- `crates/guest/src/main.rs`: SP1 guest that verifies a batch and commits public inputs
- `crates/host/src/main.rs`: host runner that assembles inputs/witnesses/proofs (JSON-driven, auto-sign)
- `contracts/src/ClobVerifier.sol`: Solidity verifier that updates canonical state root
- `contracts/test/ClobVerifier.t.sol`: Solidity unit tests
- `contracts/test/ClobVerifierFixture.t.sol`: Solidity fixture test
- `spec/SPEC.md`: normative protocol spec
- `examples/input.json`: example batch + state input
- `scripts/run_clob_example.sh`: end-to-end host execution
- `contracts/testdata/proof.json`: fixture public inputs for Solidity tests

## Quickstart

```sh
cargo test -p clob-core
```

```sh
sh scripts/run_clob_example.sh
```

```sh
cd contracts && forge test -v
```

## Protocol/Engine overview

- Spot-only continuous CLOB (limit orders only, GTC/IOC)
- Deterministic price-time FIFO at each tick; maker-price execution; partial fills allowed
- Taker fee charged in quote; deterministic rounding (see `spec/SPEC.md`)

## Commitments & Public Inputs

All commitments use Keccak-256. State is a 256-bit sparse Merkle map with:
- leaf hash `keccak256(0x00 || key32 || valueHash32)` for non-empty values
- node hash `keccak256(0x01 || left32 || right32)`
- empty leaf = `0x00..00`

Public input schema (fixed-width, big-endian):

```solidity
struct PublicInputs {
    bytes32 prevRoot;
    bytes32 newRoot;
    bytes32 batchDigest;
    bytes32 rulesHash;
    bytes32 domainSeparator;
    uint64  batchSeq;
    uint64  batchTimestamp;
    bytes32 daCommitment;
    bytes32 tradesRoot;
    bytes32 feesRoot;
}
```

See `spec/SPEC.md` for the exact encoding and hashing rules.

## How it works

- Offchain: build batch + membership proofs; compute `batchDigest` and witness data
- SP1 guest: verify signatures/nonces, execute deterministic matching, update sparse Merkle root
- Onchain: Solidity verifier checks proof and updates canonical root

## Security / determinism guarantees

- Signature verification and strict nonce sequencing per account
- Batch sequencing enforced by `batchSeq`
- Omission resistance via best-tick pointers + linked-list invariants for ticks/orders
- Checked arithmetic with balance caps; deterministic rounding rules
- Byte-precise encoding and hashing; `spec/SPEC.md` is the normative reference

## Spec

See `spec/SPEC.md`.
