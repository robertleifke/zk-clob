// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proof) external view;
}

contract ClobVerifier {
    struct MarketState {
        bytes32 root;
        uint64 batchSeq;
    }

    struct PublicInputs {
        bytes32 prevRoot;
        bytes32 newRoot;
        bytes32 batchDigest;
        bytes32 rulesHash;
        bytes32 domainSeparator;
        uint64 batchSeq;
        uint64 batchTimestamp;
        bytes32 daCommitment;
        bytes32 tradesRoot;
        bytes32 feesRoot;
    }

    event BatchAccepted(
        bytes32 indexed domainSeparator,
        bytes32 prevRoot,
        bytes32 newRoot,
        bytes32 batchDigest,
        bytes32 tradesRoot,
        bytes32 feesRoot,
        uint64 batchSeq,
        uint64 batchTimestamp,
        bytes32 rulesHash,
        bytes32 daCommitment
    );

    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;
    mapping(bytes32 => MarketState) public markets;

    constructor(address verifier_, bytes32 programVKey_) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
    }

    function verifyAndUpdate(PublicInputs calldata inputs, bytes calldata proof) external {
        MarketState storage state = markets[inputs.domainSeparator];
        require(inputs.batchSeq == state.batchSeq + 1, "batchSeq mismatch");
        require(inputs.prevRoot == state.root, "prevRoot mismatch");

        bytes memory publicValues = encodePublicInputs(inputs);
        verifier.verifyProof(programVKey, publicValues, proof);

        state.root = inputs.newRoot;
        state.batchSeq = inputs.batchSeq;

        emit BatchAccepted(
            inputs.domainSeparator,
            inputs.prevRoot,
            inputs.newRoot,
            inputs.batchDigest,
            inputs.tradesRoot,
            inputs.feesRoot,
            inputs.batchSeq,
            inputs.batchTimestamp,
            inputs.rulesHash,
            inputs.daCommitment
        );
    }

    function encodePublicInputs(PublicInputs calldata inputs) public pure returns (bytes memory) {
        return abi.encodePacked(
            inputs.prevRoot,
            inputs.newRoot,
            inputs.batchDigest,
            inputs.rulesHash,
            inputs.domainSeparator,
            _u64be(inputs.batchSeq),
            _u64be(inputs.batchTimestamp),
            inputs.daCommitment,
            inputs.tradesRoot,
            inputs.feesRoot
        );
    }

    function _u64be(uint64 value) internal pure returns (bytes8 out) {
        out = bytes8(
            (uint64(uint8(value >> 56)) << 56) |
            (uint64(uint8(value >> 48)) << 48) |
            (uint64(uint8(value >> 40)) << 40) |
            (uint64(uint8(value >> 32)) << 32) |
            (uint64(uint8(value >> 24)) << 24) |
            (uint64(uint8(value >> 16)) << 16) |
            (uint64(uint8(value >> 8)) << 8) |
            uint64(uint8(value))
        );
    }
}
