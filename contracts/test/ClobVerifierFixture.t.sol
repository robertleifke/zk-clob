// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "../src/ClobVerifier.sol";

contract FixtureVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure override {}
}

contract ClobVerifierFixtureTest is Test {
    using stdJson for string;

    function testFixturePublicValuesMatch() public {
        string memory json = vm.readFile("testdata/proof.json");
        bytes32 prevRoot = json.readBytes32(".prev_root");
        bytes32 newRoot = json.readBytes32(".new_root");
        bytes32 batchDigest = json.readBytes32(".batch_digest");
        bytes32 rulesHash = json.readBytes32(".rules_hash");
        bytes32 domainSeparator = json.readBytes32(".domain_separator");
        bytes32 tradesRoot = json.readBytes32(".trades_root");
        bytes32 feesRoot = json.readBytes32(".fees_root");
        bytes32 daCommitment = json.readBytes32(".da_commitment");
        uint64 batchSeq = uint64(json.readUint(".batch_seq"));
        uint64 batchTimestamp = uint64(json.readUint(".batch_timestamp"));
        bytes memory publicValues = json.readBytes(".public_values");

        ClobVerifier verifier = new ClobVerifier(address(new FixtureVerifier()), bytes32(uint256(1)));
        ClobVerifier.PublicInputs memory inputs = ClobVerifier.PublicInputs({
            prevRoot: prevRoot,
            newRoot: newRoot,
            batchDigest: batchDigest,
            rulesHash: rulesHash,
            domainSeparator: domainSeparator,
            batchSeq: batchSeq,
            batchTimestamp: batchTimestamp,
            daCommitment: daCommitment,
            tradesRoot: tradesRoot,
            feesRoot: feesRoot
        });

        bytes memory encoded = verifier.encodePublicInputs(inputs);
        assertEq(keccak256(encoded), keccak256(publicValues));
    }
}
