// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ClobVerifier.sol";

contract MockVerifier is ISP1Verifier {
    bytes public lastPublicValues;
    bytes public lastProof;
    bytes32 public lastVKey;

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proof) external view override {
        programVKey;
        publicValues;
        proof;
    }

    function record(bytes32 programVKey, bytes calldata publicValues, bytes calldata proof) external {
        lastVKey = programVKey;
        lastPublicValues = publicValues;
        lastProof = proof;
    }
}

contract ClobVerifierTest is Test {
    ClobVerifier verifier;
    MockVerifier mock;

    function setUp() public {
        mock = new MockVerifier();
        verifier = new ClobVerifier(address(mock), bytes32(uint256(1)));
    }

    function testVerifyAndUpdateHappyPath() public {
        ClobVerifier.PublicInputs memory inputs = ClobVerifier.PublicInputs({
            prevRoot: bytes32(0),
            newRoot: bytes32(uint256(2)),
            batchDigest: bytes32(uint256(3)),
            rulesHash: bytes32(uint256(4)),
            domainSeparator: bytes32(uint256(5)),
            batchSeq: 1,
            batchTimestamp: 1234,
            daCommitment: bytes32(uint256(6)),
            tradesRoot: bytes32(uint256(7)),
            feesRoot: bytes32(uint256(8))
        });
        verifier.verifyAndUpdate(inputs, hex"deadbeef");
        (bytes32 root, uint64 seq) = verifier.markets(inputs.domainSeparator);
        assertEq(root, inputs.newRoot);
        assertEq(seq, 1);
    }

    function testBatchSeqMismatch() public {
        ClobVerifier.PublicInputs memory inputs = ClobVerifier.PublicInputs({
            prevRoot: bytes32(0),
            newRoot: bytes32(uint256(2)),
            batchDigest: bytes32(uint256(3)),
            rulesHash: bytes32(uint256(4)),
            domainSeparator: bytes32(uint256(5)),
            batchSeq: 2,
            batchTimestamp: 1234,
            daCommitment: bytes32(uint256(6)),
            tradesRoot: bytes32(uint256(7)),
            feesRoot: bytes32(uint256(8))
        });
        vm.expectRevert("batchSeq mismatch");
        verifier.verifyAndUpdate(inputs, hex"deadbeef");
    }

    function testPrevRootMismatch() public {
        ClobVerifier.PublicInputs memory inputs = ClobVerifier.PublicInputs({
            prevRoot: bytes32(uint256(9)),
            newRoot: bytes32(uint256(2)),
            batchDigest: bytes32(uint256(3)),
            rulesHash: bytes32(uint256(4)),
            domainSeparator: bytes32(uint256(5)),
            batchSeq: 1,
            batchTimestamp: 1234,
            daCommitment: bytes32(uint256(6)),
            tradesRoot: bytes32(uint256(7)),
            feesRoot: bytes32(uint256(8))
        });
        vm.expectRevert("prevRoot mismatch");
        verifier.verifyAndUpdate(inputs, hex"deadbeef");
    }
}
