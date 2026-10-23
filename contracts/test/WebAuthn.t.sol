// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WebAuthn} from "../src/WebAuthn.sol";

contract WebAuthnTest is Test {
    /**
     * This EVM has no P-256 precompile, and that is recorded rather than
     * worked around.
     *
     * EIP-7951 is live on Sepolia — `npm run check:p256` proves it against the
     * real chain — but Foundry 1.2.3 does not implement it at any evm_version,
     * and forking does not help because Foundry executes with its own EVM
     * rather than the remote node's. Mocking the precompile would make every
     * passkey assertion in this suite verify against nothing, so it is not
     * mocked: the signature path is proven by a real Sepolia transaction
     * instead (scripts/accept-onchain.mjs), and everything around it is tested
     * here.
     *
     * When this test starts failing, the toolchain has gained the precompile
     * and the assertion tests can move off chain.
     */
    function test_precompileIsAbsentLocally() public view {
        (bool ok, bytes memory out) = WebAuthn.P256_VERIFY.staticcall(new bytes(160));
        assertTrue(ok, "staticcall to an empty account should not revert");
        assertEq(out.length, 0, "this EVM now HAS the precompile - see the comment above");
    }

    /// And so a verification attempt is false locally, never a revert.
    function test_verifyIsFalseWithoutThePrecompile() public view {
        assertFalse(WebAuthn.p256Verify(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), bytes32(uint256(4)), bytes32(uint256(5))));
    }

    function test_base64urlEncodesAChallenge() public pure {
        // keccak256("") — a fixed value, so the expected string is fixed too.
        bytes32 v = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        assertEq(
            WebAuthn.base64urlEncode32(v),
            "xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e_rYBF2FpHA"
        );
    }

    function test_base64urlIs43CharsAndUrlSafe() public pure {
        string memory s = WebAuthn.base64urlEncode32(bytes32(type(uint256).max));
        bytes memory b = bytes(s);
        assertEq(b.length, 43);
        for (uint256 i = 0; i < b.length; i++) {
            assertTrue(b[i] != "+" && b[i] != "/" && b[i] != "=", "not url-safe");
        }
    }

    function test_hasAtMatchesOnlyAtTheGivenOffset() public pure {
        bytes memory json = '{"type":"webauthn.get"}';
        assertTrue(WebAuthn.hasAt(json, 1, '"type":"webauthn.get"'));
        assertFalse(WebAuthn.hasAt(json, 0, '"type":"webauthn.get"'));
        assertFalse(WebAuthn.hasAt(json, 2, '"type":"webauthn.get"'));
    }

    function test_hasAtRefusesToReadPastTheEnd() public pure {
        assertFalse(WebAuthn.hasAt(bytes("abc"), 1, bytes("bcde")));
    }

    function test_quotedHashReadsToTheClosingQuote() public pure {
        bytes memory json = '{"origin":"https://v1.id.example.com","x":1}';
        // 11 is just past the opening quote of the value.
        assertEq(
            WebAuthn.quotedHashAt(json, 11),
            keccak256("https://v1.id.example.com")
        );
    }

    function test_quotedHashRefusesAnEscapedValue() public pure {
        bytes memory json = '{"origin":"https://a\\"b"}';
        assertEq(WebAuthn.quotedHashAt(json, 11), bytes32(0));
    }

    function test_containsFindsCrossOrigin() public pure {
        assertTrue(WebAuthn.contains(bytes('{"crossOrigin":true}'), '"crossOrigin":true'));
        assertFalse(WebAuthn.contains(bytes('{"crossOrigin":false}'), '"crossOrigin":true'));
    }
}
