// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HegotaSupport} from "@forshtat/hegota-support/contracts/HegotaSupport.sol";
import {Devnet} from "@forshtat/hegota-support/contracts/Devnet.sol";
import {Scope, TxParam, FrameParam} from "@forshtat/hegota-support/contracts/Params.sol";

/// The account a delivery is sent from: authorised by Bob's email reply and nothing else.
///
/// The frame's `data` carries the DKIM public modulus, the 256-byte signature, and the signed header bytes.
/// Unlike a transaction signature this is not circular: a DKIM signature covers the email, not the frame, so
/// it can live in frame data (which `sigHash` does cover) without changing as the hash changes.
///
/// The modulus is passed in rather than stored, and only its keccak hash is pinned. That keeps the DKIM key
/// where it really lives (DNS) while still binding this account to one key, and it avoids ~17k gas of cold
/// SLOADs inside a validation prefix capped at MAX_VERIFY_GAS = 100,000.
contract DkimWallet is HegotaSupport(Devnet.ERC8421_WORKSHOP) {
    /// EM bytes 0..31: 0x00 0x01 then the first 30 bytes of the 0xFF padding.
    bytes32 internal constant FIRST_WORD = 0x0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    /// EM bytes 192..223: the last 12 bytes of padding, the 0x00 separator, and the SHA-256 DigestInfo.
    bytes32 internal constant DIGEST_INFO_WORD = 0xffffffffffffffffffffffff003031300d060960864801650304020105000420;

    bytes32 public immutable modulusHash;

    /// The only contract this account will approve a release to.
    address public immutable releaseTarget;

    constructor(bytes32 modulusHash_, address releaseTarget_) payable {
        modulusHash = modulusHash_;
        releaseTarget = releaseTarget_;
    }

    fallback() external payable {
        uint256 index = txparam(TxParam.CURRENT_FRAME_INDEX);
        uint256 length = frameparam(index, FrameParam.DATA_LENGTH);
        (bytes memory modulus, bytes memory signature, bytes memory signedHeaders) =
            abi.decode(framedatacopy(0, length, index), (bytes, bytes, bytes));

        require(keccak256(modulus) == modulusHash, "wrong dkim key");
        require(verify(modulus, signature, sha256(signedHeaders)), "bad dkim signature");

        // A valid signature over *some* email is not authority to release *any* delivery. The
        // frame after this one is the release, and the accept hash it writes has to be the hash of
        // the headers this signature covers — otherwise the same reply would authorise every file
        // we hold. The target is pinned too, so the approval cannot be spent on another contract.
        // Not simply the next frame: when Pinesign sponsors the gas a paymaster
        // frame sits in between. Find the frame aimed at the release contract,
        // and insist there is exactly one of them.
        bytes32 expected = keccak256(signedHeaders);
        uint256 frames = txparam(TxParam.FRAME_COUNT);
        uint256 releases = 0;
        for (uint256 i = 0; i < frames; i++) {
            if (i == index) continue;
            if (address(uint160(frameparam(i, FrameParam.RESOLVED_TARGET))) != releaseTarget) continue;
            releases++;
            // release(bytes32 acceptHash, ...): four bytes of selector, then the hash.
            require(bytes32(framedatacopy(4, 32, i)) == expected, "pinesign: accept hash mismatch");
        }
        require(releases == 1, "pinesign: one release per transaction");

        approve(Scope(frameparam(index, FrameParam.ALLOWED_SCOPE)));
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256 and e = 65537, through the MODEXP precompile at 0x05.
    ///
    /// EM is checked as eight 32-byte words rather than 253 single-byte comparisons. Indexing `bytes memory`
    /// bounds-checks every access, and indexing a `bytes constant` copies the whole constant each time; doing
    /// it byte-wise cost 246,505 gas, which does not fit a validation prefix capped at 100,000.
    ///
    /// EM = 0x00 0x01 | 0xFF * 202 | 0x00 | DigestInfo(19) | H(32)
    function verify(bytes memory modulus, bytes memory signature, bytes32 digest) public view returns (bool) {
        if (modulus.length != 256 || signature.length != 256) return false;

        bytes memory input = abi.encodePacked(
            uint256(256), uint256(3), uint256(256), signature, bytes3(0x010001), modulus
        );
        (bool ok, bytes memory em) = address(0x05).staticcall(input);
        if (!ok || em.length != 256) return false;

        bytes32 w0;
        bytes32 w6;
        bytes32 w7;
        bool padOk;
        assembly {
            let p := add(em, 32)
            w0 := mload(p)
            padOk := and(
                and(eq(mload(add(p, 32)), not(0)), eq(mload(add(p, 64)), not(0))),
                and(
                    and(eq(mload(add(p, 96)), not(0)), eq(mload(add(p, 128)), not(0))),
                    eq(mload(add(p, 160)), not(0))
                )
            )
            w6 := mload(add(p, 192))
            w7 := mload(add(p, 224))
        }
        return padOk && w0 == FIRST_WORD && w6 == DIGEST_INFO_WORD && w7 == digest;
    }
}
