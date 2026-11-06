// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HegotaSupport} from "@forshtat/hegota-support/contracts/HegotaSupport.sol";
import {Devnet} from "@forshtat/hegota-support/contracts/Devnet.sol";
import {Scope, TxParam} from "@forshtat/hegota-support/contracts/Params.sol";

/// Spike 5b: an EIP-8141 account whose only owner is a P-256 (passkey) key.
///
/// The devnet profile declares a native `P256 = 0x2` signature scheme, but the support library has no code
/// path for it, so this wallet does not rely on the protocol verifying P-256. It carries the signature in an
/// ARBITRARY signature entry and verifies it itself, with the EIP-7951 precompile at 0x100 (LIVE on this
/// devnet: probed, 6,900 gas).
///
/// Why a signature entry and not frame data: `sigHash` elides the `signature` bytes of every entry whose
/// `msg` is empty, so the key can sign the hash without the signature changing it. Frame data is covered by
/// the hash, so putting r||s there would be circular.
///
/// The message signed here is the raw transaction signature hash. A real passkey signs
/// `sha256(authenticatorData || sha256(clientDataJSON))` with the tx hash as the challenge; that wrapping is
/// PineSign's WebAuthn.sol, already covered by its contract tests, and layers on top of this without change.
contract P256Wallet is HegotaSupport(Devnet.ERC8421_WORKSHOP) {
    address internal constant P256_VERIFY = address(0x100);

    bytes32 public immutable qx;
    bytes32 public immutable qy;

    constructor(bytes32 qx_, bytes32 qy_) payable {
        qx = qx_;
        qy = qy_;
    }

    /// The VERIFY frame whose target is this wallet lands here.
    fallback() external payable {
        bytes memory rs = sigdatacopy(0, 64, 0);
        require(rs.length == 64, "need r||s");
        bytes32 digest = bytes32(txparam(TxParam.SIG_HASH));
        (bool ok, bytes memory ret) = P256_VERIFY.staticcall(abi.encodePacked(digest, rs, qx, qy));
        require(ok && ret.length == 32 && uint256(bytes32(ret)) == 1, "bad p256 signature");
        approve(Scope.EXECUTION_AND_PAYMENT);
    }
}
