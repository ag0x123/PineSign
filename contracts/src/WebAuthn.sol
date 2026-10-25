// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * WebAuthn assertion verification, on chain.
 *
 * `verify` and `originHashOf` are `public`, which makes this a deployed
 * library reached by delegatecall rather than code inlined into every caller.
 * The byte-walking in here is most of the logic, and a contract that embedded
 * it paid for it in deployment size; linking means the delivery contract
 * carries a call instead of a copy, and a second contract that needs passkey
 * verification reuses this one.
 *
 * The point of doing this here rather than on a server is that nobody has to
 * be trusted to have done it. A passkey tap becomes a fact the contract
 * checked for itself, so "Bob accepted this file" is not something a gateway
 * asserts — it is something anyone can re-derive from the chain.
 *
 * P-256 verification is the EIP-7951 precompile at 0x100, which is live on
 * Sepolia and mainnet and costs 6,900 gas. There is deliberately no Solidity
 * fallback: a chain without the precompile would verify at ~300k gas, which
 * changes what this protocol costs badly enough that it should be a conscious
 * redeployment rather than a silent degradation.
 *
 * clientDataJSON is not parsed as JSON. The caller says where the fields are
 * and the contract checks that what is at those offsets is exactly what it
 * must be — the approach webauthn-sol takes, because browsers do not agree on
 * key order or on which optional fields they include, and a contract that
 * rebuilt the JSON itself would reject honest authenticators.
 */
library WebAuthn {
    /// The P-256 verify precompile, EIP-7951.
    address internal constant P256_VERIFY = address(0x100);

    /// authenticatorData flags: user present, user verified.
    bytes1 internal constant FLAG_UP = 0x01;
    bytes1 internal constant FLAG_UV = 0x04;

    struct Assertion {
        bytes authenticatorData;
        bytes clientDataJSON;
        /// Where `"type":"webauthn.get"` starts in clientDataJSON.
        uint256 typeIndex;
        /// Where `"challenge":"` starts.
        uint256 challengeIndex;
        /// Where `"origin":"` starts.
        uint256 originIndex;
        bytes32 r;
        bytes32 s;
    }

    bytes internal constant TYPE_FIELD = '"type":"webauthn.get"';
    bytes internal constant CHALLENGE_FIELD = '"challenge":"';
    bytes internal constant ORIGIN_FIELD = '"origin":"';
    bytes internal constant CROSS_ORIGIN_TRUE = '"crossOrigin":true';

    /**
     * The origin this assertion claims, as a hash, so a caller can check it
     * against a set before verifying anything else.
     *
     * Returns zero when the field is not where the caller said it is, and zero
     * is never an allowed origin — so a wrong index fails closed.
     */
    function originHashOf(Assertion memory a) public pure returns (bytes32) {
        if (!hasAt(a.clientDataJSON, a.originIndex, ORIGIN_FIELD)) return bytes32(0);
        return quotedHashAt(a.clientDataJSON, a.originIndex + ORIGIN_FIELD.length);
    }

    /**
     * Verify one assertion completely.
     *
     * Every check is here and none is optional, because a WebAuthn
     * verification missing one of them still passes the happy path — which is
     * exactly how it tends to ship broken.
     */
    function verify(
        Assertion memory a,
        bytes32 challenge,
        bytes32 rpIdHash,
        bytes32 originHash,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) public view returns (bool) {
        // --- authenticatorData ---
        //
        // 32 bytes of rpIdHash, one of flags, four of counter.
        if (a.authenticatorData.length < 37) return false;

        bytes32 gotRpIdHash;
        bytes memory authData = a.authenticatorData;
        assembly {
            gotRpIdHash := mload(add(authData, 0x20))
        }
        // Binds the credential to the domain it was created for. Without this,
        // an assertion obtained on any other site would be accepted here.
        if (gotRpIdHash != rpIdHash) return false;

        bytes1 flags = a.authenticatorData[32];
        if (flags & FLAG_UP != FLAG_UP) return false;
        if (flags & FLAG_UV != FLAG_UV) return false;

        // --- clientDataJSON ---
        if (!hasAt(a.clientDataJSON, a.typeIndex, TYPE_FIELD)) return false;
        if (!hasAt(a.clientDataJSON, a.challengeIndex, CHALLENGE_FIELD)) return false;
        if (!hasAt(a.clientDataJSON, a.originIndex, ORIGIN_FIELD)) return false;

        // The challenge is what ties this tap to this transfer. It sits as 43
        // base64url characters immediately after `"challenge":"`.
        if (
            !hasAt(
                a.clientDataJSON,
                a.challengeIndex + CHALLENGE_FIELD.length,
                bytes(base64urlEncode32(challenge))
            )
        ) return false;

        // The origin must be one the sender nominated. rpIdHash already binds
        // the domain, but it binds the whole subtree — this pins the exact
        // published page.
        if (quotedHashAt(a.clientDataJSON, a.originIndex + ORIGIN_FIELD.length) != originHash) {
            return false;
        }

        // A cross-origin ceremony is one driven from inside an iframe on some
        // other site. Nothing here needs that, so it is refused outright
        // rather than reasoned about.
        if (contains(a.clientDataJSON, CROSS_ORIGIN_TRUE)) return false;

        // --- the signature itself ---
        //
        // Over authenticatorData followed by the hash of the exact
        // clientDataJSON bytes. Re-serialising either would not match.
        bytes32 digest = sha256(
            abi.encodePacked(a.authenticatorData, sha256(a.clientDataJSON))
        );

        return p256Verify(digest, a.r, a.s, pubKeyX, pubKeyY);
    }

    /// EIP-7951. Reverts nothing: a bad signature is `false`, not a failure.
    function p256Verify(bytes32 digest, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory out) = P256_VERIFY.staticcall(
            abi.encodePacked(digest, r, s, x, y)
        );
        // The precompile returns 32 bytes of 1 on success and empty on
        // failure. An empty return from a missing precompile therefore reads
        // as "did not verify", which is the safe direction.
        return ok && out.length == 32 && bytes32(out) == bytes32(uint256(1));
    }

    // ---- bytes helpers ----

    /// Is `needle` present in `haystack` starting exactly at `offset`?
    function hasAt(bytes memory haystack, uint256 offset, bytes memory needle)
        internal
        pure
        returns (bool)
    {
        if (offset + needle.length > haystack.length) return false;
        for (uint256 i = 0; i < needle.length; i++) {
            if (haystack[offset + i] != needle[i]) return false;
        }
        return true;
    }

    /// Does `haystack` contain `needle` anywhere? Used only for the one field
    /// whose position we do not ask the caller for.
    function contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        if (needle.length == 0 || needle.length > haystack.length) return false;
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) return true;
        }
        return false;
    }

    /**
     * keccak of the JSON string value starting at `offset`, up to its closing
     * quote. Escapes are not handled, and do not need to be: an origin is a
     * URL, and a URL containing a backslash or a quote is not one we allow.
     */
    function quotedHashAt(bytes memory json, uint256 offset) internal pure returns (bytes32) {
        uint256 end = offset;
        while (end < json.length && json[end] != '"') {
            // A backslash would mean the value is escaped and this naive scan
            // is reading the wrong thing. Refuse by returning a hash that
            // cannot match anything.
            if (json[end] == "\\") return bytes32(0);
            end++;
        }
        if (end >= json.length) return bytes32(0);

        bytes memory value = new bytes(end - offset);
        for (uint256 i = 0; i < value.length; i++) {
            value[i] = json[offset + i];
        }
        return keccak256(value);
    }

    bytes internal constant B64URL =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /**
     * 32 bytes as 43 base64url characters, unpadded — the form a challenge
     * takes inside clientDataJSON.
     *
     * 32 bytes is 10 full three-byte groups plus two bytes, so the tail is
     * handled on its own rather than with a padding branch in the loop.
     */
    function base64urlEncode32(bytes32 value) internal pure returns (string memory) {
        bytes memory input = abi.encodePacked(value);
        bytes memory out = new bytes(43);
        uint256 o = 0;

        for (uint256 i = 0; i < 30; i += 3) {
            uint256 group = (uint256(uint8(input[i])) << 16)
                | (uint256(uint8(input[i + 1])) << 8)
                | uint256(uint8(input[i + 2]));
            out[o++] = B64URL[(group >> 18) & 0x3f];
            out[o++] = B64URL[(group >> 12) & 0x3f];
            out[o++] = B64URL[(group >> 6) & 0x3f];
            out[o++] = B64URL[group & 0x3f];
        }

        // The last two bytes become three characters, no padding.
        uint256 tail = (uint256(uint8(input[30])) << 8) | uint256(uint8(input[31]));
        out[o++] = B64URL[(tail >> 10) & 0x3f];
        out[o++] = B64URL[(tail >> 4) & 0x3f];
        out[o++] = B64URL[(tail << 2) & 0x3f];

        return string(out);
    }
}
