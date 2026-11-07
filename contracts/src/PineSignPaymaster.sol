// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HegotaSupport} from "@forshtat/hegota-support/contracts/HegotaSupport.sol";
import {Devnet} from "@forshtat/hegota-support/contracts/Devnet.sol";
import {Scope, TxParam, FrameParam} from "@forshtat/hegota-support/contracts/Params.sol";

/// Pinesign pays the gas for a delivery. A sender's account is a passkey that has never held ETH,
/// and we do not want to teach anyone what a faucet is.
///
/// It sponsors a transaction only if the gateway said so, and it finds that out without reading a
/// single storage slot. The gateway signs `(chainId, paymaster, sender, nonce)` off chain and the
/// signature travels in this frame's data; the fallback recovers it and compares against a signer
/// fixed at construction. Everything it needs is either an immutable or a transaction parameter.
///
/// That shape is forced. The first version kept a credits mapping and decremented it here, and the
/// node refused the transaction with `StorageReadNonSender`: during validation an unstaked entity
/// may only touch the sender's own storage. Paying for anyone instead would have left the balance
/// drainable by whoever cared to name this contract in a frame. A signature costs ~3,000 gas and
/// closes that without staking.
///
/// What is still a gateway decision rather than a chain-enforced one is the allowance — how many
/// free sends an account gets. The gateway simply does not sign the sponsorship beyond that, which
/// is enough, because without the signature there is no sponsorship.
///
/// It cannot look at its own balance: BALANCE and SELFBALANCE are banned during validation too, so
/// running dry shows up at settlement rather than as a refusal. The health endpoint watches it.
contract PineSignPaymaster is HegotaSupport(Devnet.ERC8421_WORKSHOP) {
    address public immutable owner;

    /// Whoever holds this key decides what gets sponsored. Immutable, so checking it is free of storage.
    address public immutable sponsor;

    /// CHAINID is an environment opcode and validation may not use one, so the value is baked in.
    uint256 public immutable chainId;

    constructor(address sponsor_, uint256 chainId_) payable {
        owner = msg.sender;
        sponsor = sponsor_;
        chainId = chainId_;
    }

    /// The VERIFY frame whose target is this paymaster lands here.
    fallback() external payable {
        uint256 index = txparam(TxParam.CURRENT_FRAME_INDEX);
        require(frameparam(index, FrameParam.DATA_LENGTH) == 65, "pinesign: need a 65-byte sponsorship");
        bytes memory signature = framedatacopy(0, 65, index);

        // The nonce is in the digest, so a sponsorship can be spent once and only by the account it
        // names. Nothing else about the transaction is covered, which is deliberate: the gateway is
        // agreeing to pay for this account's next transaction, not auditing what it does.
        bytes32 digest = keccak256(
            abi.encode(chainId, address(this), address(uint160(txparam(TxParam.SENDER))), txparam(TxParam.NONCE))
        );

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            let p := add(signature, 32)
            r := mload(p)
            s := mload(add(p, 32))
            v := byte(0, mload(add(p, 64)))
        }
        require(ecrecover(digest, v, r, s) == sponsor, "pinesign: not sponsored");

        approve(Scope.PAYMENT);
    }

    /// The same check, callable off chain, so a sponsorship can be debugged without spending a
    /// transaction to find out which of the two requires above failed.
    function recoverSponsor(address sender, uint256 nonce, bytes calldata signature) external view returns (address) {
        bytes32 digest = keccak256(abi.encode(chainId, address(this), sender, nonce));
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            let p := signature.offset
            r := calldataload(p)
            s := calldataload(add(p, 32))
            v := byte(0, calldataload(add(p, 64)))
        }
        return ecrecover(digest, v, r, s);
    }

    /// Top up. A plain transfer would run the fallback, which calls APPROVE outside a frame and fails.
    function fund() external payable {}

    function withdraw(address payable to, uint256 amount) external {
        require(msg.sender == owner, "pinesign: not owner");
        to.transfer(amount);
    }
}
