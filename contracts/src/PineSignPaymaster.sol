// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HegotaSupport} from "@forshtat/hegota-support/contracts/HegotaSupport.sol";
import {Devnet} from "@forshtat/hegota-support/contracts/Devnet.sol";
import {Scope} from "@forshtat/hegota-support/contracts/Params.sol";

/// Pinesign pays the gas for a delivery. A sender's account is a passkey that has never held ETH,
/// and we do not want to teach anyone what a faucet is.
///
/// It counts nothing and checks nobody, which is not where this started. The first version kept a
/// credits mapping and decremented it in the validation frame; the node refused the transaction
/// with `StorageReadNonSender`, because an unstaked entity may only touch the sender's own storage
/// during validation — its own storage included only if it is the sender. Staking to unlock that
/// read buys nothing here: the gateway is the only party that builds these transactions, so the
/// free-send allowance is its decision to make and it can make it before spending any gas.
///
/// So the honest description is: this contract pays while it has ETH, the gateway decides who gets
/// a transaction built in the first place, and the allowance is a gateway policy rather than a
/// chain-enforced one. Anyone who could submit a frame transaction naming this paymaster directly
/// could spend its balance.
///
/// It also cannot look at its own balance — BALANCE and SELFBALANCE are banned during validation
/// too — so running dry shows up at settlement rather than as a polite refusal. The health
/// endpoint watches the balance for that reason.
contract PineSignPaymaster is HegotaSupport(Devnet.ERC8421_WORKSHOP) {
    address public immutable owner;

    constructor() payable {
        owner = msg.sender;
    }

    /// The VERIFY frame whose target is this paymaster lands here.
    fallback() external payable {
        approve(Scope.PAYMENT);
    }

    /// Top up. A plain transfer would run the fallback, which calls APPROVE outside a frame and fails.
    function fund() external payable {}

    function withdraw(address payable to, uint256 amount) external {
        require(msg.sender == owner, "pinesign: not owner");
        to.transfer(amount);
    }
}
