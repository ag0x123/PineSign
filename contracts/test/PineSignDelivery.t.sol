// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PineSignDelivery} from "../src/PineSignDelivery.sol";
import {WebAuthn} from "../src/WebAuthn.sol";

/**
 * The delivery state machine.
 *
 * One thing is missing from this suite and it is missing on purpose: a passkey
 * assertion that actually verifies. This EVM has no P-256 precompile (see
 * WebAuthn.t.sol), and mocking it would mean every acceptance here verified
 * against nothing at all. So `accept` is tested up to the signature — every
 * state and timing check that guards it, and the fact that a bad assertion is
 * refused — and the signature itself is proven by a real Sepolia transaction.
 */
contract PineSignDeliveryTest is Test {
    PineSignDelivery delivery;

    address alice = address(0xA11CE);
    address releaser = address(0xBEEF);
    address relayer = address(0xDEAD);

    bytes32 constant B = keccak256("the half the sender holds back");
    /**
     * Held in storage, not declared `constant`.
     *
     * `sha256` compiles to a staticcall to the precompile at 0x2, and a
     * `constant` is inlined at every use — so a `constant` spelled this way
     * makes a real external call wherever it appears. That silently eats the
     * next `vm.prank` or satisfies the next `vm.expectRevert`, which is a
     * confusing way to lose an afternoon.
     */
    bytes32 rpIdHash = sha256("id.example.com");
    bytes32 constant ORIGIN_HASH = keccak256("https://v1.id.example.com");
    uint64 acceptBy;
    uint64 releaseBy;

    function setUp() public {
        bytes32[] memory origins = new bytes32[](1);
        origins[0] = ORIGIN_HASH;
        delivery = new PineSignDelivery(rpIdHash, origins);
        vm.warp(1_700_000_000);
        acceptBy = uint64(block.timestamp + 1 days);
        releaseBy = uint64(block.timestamp + 2 days);
        baseParams = buildParams();
    }

    /**
     * Built once in setUp, not per call.
     *
     * `sha256` in Solidity is a staticcall to the precompile at 0x2, and
     * `vm.prank` applies to the next call of any kind — so computing this
     * after a prank silently spends the prank on the hash and sends the
     * transaction as the test contract instead.
     */
    PineSignDelivery.SendParams baseParams;

    function params() internal view returns (PineSignDelivery.SendParams memory) {
        return baseParams;
    }

    function buildParams() internal view returns (PineSignDelivery.SendParams memory) {
        return PineSignDelivery.SendParams({
            releaser: releaser,
            passkeyX: bytes32(uint256(0x1111)),
            passkeyY: bytes32(uint256(0x2222)),
            pkBX: bytes32(uint256(0x3333)),
            pkBOdd: false,
            ephemeralX: bytes32(uint256(0x4444)),
            ephemeralOdd: true,
            swarmRef: keccak256("swarm"),
            ciphertextHash: keccak256("C"),
            plaintextCommitment: keccak256(abi.encode(keccak256("salt||F"))),
            releaseCommitment: keccak256(abi.encode(B)),
            descriptionHash: keccak256("an invoice"),
            acceptBy: acceptBy,
            releaseBy: releaseBy
        });
    }

    function sendOne() internal returns (bytes32) {
        PineSignDelivery.SendParams memory p = params();
        vm.prank(alice);
        return delivery.send(p);
    }

    /// An assertion that is well-formed but cannot verify without a precompile.
    function emptyAssertion() internal pure returns (WebAuthn.Assertion memory) {
        bytes memory authData = new bytes(37);
        authData[32] = 0x05; // UP | UV
        return WebAuthn.Assertion({
            authenticatorData: authData,
            clientDataJSON: bytes('{"type":"webauthn.get","challenge":"","origin":"https://v1.id.example.com"}'),
            typeIndex: 1,
            challengeIndex: 23,
            originIndex: 38,
            r: bytes32(uint256(1)),
            s: bytes32(uint256(2))
        });
    }

    // ---- send ----

    function test_sendStartsInSent() public {
        bytes32 id = sendOne();
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Sent));
    }

    function test_sendRecordsEveryCommitment() public {
        bytes32 id = sendOne();
        PineSignDelivery.Delivery memory d = delivery.get(id);
        assertEq(d.sender, alice);
        assertEq(d.releaser, releaser);
        assertEq(d.releaseCommitment, keccak256(abi.encode(B)));
        assertEq(d.ciphertextHash, keccak256("C"));
        assertEq(d.releasedKey, bytes32(0), "B must not be on chain yet");
    }

    /// The releaser is separable from the sender, which is the whole point of it.
    function test_senderIsReleaserWhenUnspecified() public {
        PineSignDelivery.SendParams memory p = params();
        p.releaser = address(0);
        vm.prank(alice);
        bytes32 id = delivery.send(p);
        assertEq(delivery.get(id).releaser, alice);
    }

    function test_idIsDerivedNotChosen() public {
        bytes32 id = sendOne();
        assertEq(id, delivery.transferId(alice, params()));
    }

    function test_oneFieldChangedIsADifferentTransfer() public {
        PineSignDelivery.SendParams memory p = params();
        p.ciphertextHash = keccak256("a different ciphertext");
        assertTrue(delivery.transferId(alice, p) != delivery.transferId(alice, params()));
    }

    function test_sendIsWriteOnce() public {
        sendOne();
        PineSignDelivery.SendParams memory p = params();
        // The same params from the same sender reuse the ephemeral key, which
        // is refused before the duplicate id is even reached.
        vm.prank(alice);
        vm.expectRevert(PineSignDelivery.EphemeralReused.selector);
        delivery.send(p);
    }

    function test_aReusedEphemeralKeyIsRefused() public {
        sendOne();
        PineSignDelivery.SendParams memory p = params();
        p.ciphertextHash = keccak256("another file entirely");
        vm.prank(alice);
        vm.expectRevert(PineSignDelivery.EphemeralReused.selector);
        delivery.send(p);
    }

    function test_aFreshEphemeralKeyIsFine() public {
        sendOne();
        PineSignDelivery.SendParams memory p = params();
        p.ephemeralX = bytes32(uint256(0x5555));
        vm.prank(alice);
        delivery.send(p);
    }

    function test_deadlinesMustBeOrdered() public {
        PineSignDelivery.SendParams memory p = params();
        p.releaseBy = p.acceptBy;
        vm.prank(alice);
        vm.expectRevert(PineSignDelivery.DeadlinesOutOfOrder.selector);
        delivery.send(p);
    }

    function test_anAcceptDeadlineInThePastIsRefused() public {
        PineSignDelivery.SendParams memory p = params();
        p.acceptBy = uint64(block.timestamp);
        vm.prank(alice);
        vm.expectRevert(PineSignDelivery.AcceptWindowClosed.selector);
        delivery.send(p);
    }

    function test_anEmptyReleaseCommitmentIsRefused() public {
        PineSignDelivery.SendParams memory p = params();
        p.releaseCommitment = bytes32(0);
        vm.prank(alice);
        vm.expectRevert(PineSignDelivery.EmptyField.selector);
        delivery.send(p);
    }

    function test_anEmptyPasskeyIsRefused() public {
        PineSignDelivery.SendParams memory p = params();
        p.passkeyX = bytes32(0);
        p.passkeyY = bytes32(0);
        vm.prank(alice);
        vm.expectRevert(PineSignDelivery.EmptyField.selector);
        delivery.send(p);
    }

    // ---- accept ----

    function test_acceptOnAnUnknownTransferIsRefused() public {
        vm.expectRevert(PineSignDelivery.UnknownTransfer.selector);
        delivery.accept(keccak256("nothing"), emptyAssertion());
    }

    function test_acceptAfterTheWindowIsRefused() public {
        bytes32 id = sendOne();
        vm.warp(acceptBy + 1);
        vm.expectRevert(PineSignDelivery.AcceptWindowClosed.selector);
        delivery.accept(id, emptyAssertion());
    }

    /// Without a verifying signature nothing advances — which is the property
    /// that matters even though the precompile is what proves it.
    function test_aBadAssertionIsRefused() public {
        bytes32 id = sendOne();
        vm.prank(relayer);
        vm.expectRevert(PineSignDelivery.BadAssertion.selector);
        delivery.accept(id, emptyAssertion());
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Sent));
    }

    function test_acceptAfterAbortIsRefused() public {
        bytes32 id = sendOne();
        vm.prank(alice);
        delivery.abortSend(id);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.SenderAborted)
        );
        delivery.accept(id, emptyAssertion());
    }

    function test_theAcceptDigestIsBoundToTheTransferAndTheChain() public {
        bytes32 id = sendOne();
        bytes32 digest = delivery.acceptDigest(id);
        assertTrue(digest != bytes32(0));

        // A different chain id must give a different digest, or a signature
        // could be replayed from a testnet onto mainnet.
        vm.chainId(block.chainid + 1);
        assertTrue(delivery.acceptDigest(id) != digest, "digest is not chain-bound");
    }

    function test_theAcceptDigestNeedsAKnownTransfer() public {
        vm.expectRevert(PineSignDelivery.UnknownTransfer.selector);
        delivery.acceptDigest(keccak256("nothing"));
    }

    // ---- release ----

    function test_releaseBeforeAcceptIsRefused() public {
        bytes32 id = sendOne();
        vm.prank(releaser);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.Sent)
        );
        delivery.release(id, B);
    }

    function test_releaseOnAnUnknownTransferIsRefused() public {
        vm.prank(releaser);
        vm.expectRevert(PineSignDelivery.UnknownTransfer.selector);
        delivery.release(keccak256("nothing"), B);
    }

    // ---- abort ----

    function test_onlyTheSenderMayAbort() public {
        bytes32 id = sendOne();
        vm.prank(relayer);
        vm.expectRevert(PineSignDelivery.NotSender.selector);
        delivery.abortSend(id);
    }

    function test_abortLeavesTheRecordSayingSo() public {
        bytes32 id = sendOne();
        vm.prank(alice);
        delivery.abortSend(id);
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.SenderAborted));
    }

    function test_abortIsOnlyOnce() public {
        bytes32 id = sendOne();
        vm.prank(alice);
        delivery.abortSend(id);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.SenderAborted)
        );
        delivery.abortSend(id);
    }

    // ---- expire ----

    function test_cannotExpireBeforeTheDeadline() public {
        bytes32 id = sendOne();
        vm.expectRevert(PineSignDelivery.StillInTime.selector);
        delivery.expire(id);
    }

    function test_anUnacceptedTransferLapses() public {
        bytes32 id = sendOne();
        vm.warp(acceptBy + 1);
        delivery.expire(id);
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Expired));
        assertFalse(delivery.senderDefaulted(id), "nobody accepted, so nobody defaulted");
    }

    function test_anyoneMayRecordALapse() public {
        bytes32 id = sendOne();
        vm.warp(acceptBy + 1);
        vm.prank(relayer);
        delivery.expire(id);
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Expired));
    }

    function test_expiringAnUnknownTransferIsRefused() public {
        vm.expectRevert(PineSignDelivery.UnknownTransfer.selector);
        delivery.expire(keccak256("nothing"));
    }

    function test_anAbortedTransferCannotLapse() public {
        bytes32 id = sendOne();
        vm.prank(alice);
        delivery.abortSend(id);
        vm.warp(acceptBy + 1);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.SenderAborted)
        );
        delivery.expire(id);
    }
}

/**
 * The half of the state machine that lies beyond `accept`.
 *
 * Reaching `Accepted` needs a passkey assertion that verifies, and this EVM
 * cannot execute the P-256 precompile. So this harness advances that one step
 * and nothing else: `release`, `expire` and `senderDefaulted` below are the
 * real inherited functions, running against real state.
 *
 * What is skipped here is exactly what a real Sepolia transaction proves
 * instead. Nothing else about the contract is stubbed, and the harness is
 * never deployed.
 */
contract DeliveryHarness is PineSignDelivery {
    constructor(bytes32 rpIdHash_, bytes32[] memory origins) PineSignDelivery(rpIdHash_, origins) {}

    function markAccepted(bytes32 id) external {
        Delivery storage d = _deliveries[id];
        require(d.state == State.Sent, "harness: not sent");
        d.state = State.Accepted;
        d.acceptedAt = uint64(block.timestamp);
    }
}

contract PineSignDeliveryAfterAcceptTest is Test {
    DeliveryHarness delivery;

    address alice = address(0xA11CE);
    address releaser = address(0xBEEF);
    address relayer = address(0xDEAD);

    bytes32 constant B = keccak256("the half the sender holds back");
    /**
     * Held in storage, not declared `constant`.
     *
     * `sha256` compiles to a staticcall to the precompile at 0x2, and a
     * `constant` is inlined at every use — so a `constant` spelled this way
     * makes a real external call wherever it appears. That silently eats the
     * next `vm.prank` or satisfies the next `vm.expectRevert`, which is a
     * confusing way to lose an afternoon.
     */
    bytes32 rpIdHash = sha256("id.example.com");
    bytes32 constant ORIGIN_HASH = keccak256("https://v1.id.example.com");
    PineSignDelivery.SendParams baseParams;
    uint64 acceptBy;
    uint64 releaseBy;

    function setUp() public {
        bytes32[] memory origins = new bytes32[](1);
        origins[0] = ORIGIN_HASH;
        delivery = new DeliveryHarness(rpIdHash, origins);
        vm.warp(1_700_000_000);
        acceptBy = uint64(block.timestamp + 1 days);
        releaseBy = uint64(block.timestamp + 2 days);
        baseParams = PineSignDelivery.SendParams({
            releaser: releaser,
            passkeyX: bytes32(uint256(0x1111)),
            passkeyY: bytes32(uint256(0x2222)),
            pkBX: bytes32(uint256(0x3333)),
            pkBOdd: false,
            ephemeralX: bytes32(uint256(0x4444)),
            ephemeralOdd: true,
            swarmRef: keccak256("swarm"),
            ciphertextHash: keccak256("C"),
            plaintextCommitment: keccak256(abi.encode(keccak256("salt||F"))),
            releaseCommitment: keccak256(abi.encode(B)),
            descriptionHash: keccak256("an invoice"),
            acceptBy: acceptBy,
            releaseBy: releaseBy
        });
    }

    function accepted() internal returns (bytes32 id) {
        PineSignDelivery.SendParams memory p = baseParams;
        vm.prank(alice);
        id = delivery.send(p);
        delivery.markAccepted(id);
    }

    // ---- release ----

    function test_theReleaserReleasesAndBGoesOnChain() public {
        bytes32 id = accepted();
        vm.prank(releaser);
        delivery.release(id, B);

        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Released));
        assertEq(delivery.get(id).releasedKey, B, "B is what the recipient was waiting for");
        assertTrue(delivery.isReleased(id));
    }

    /// The ordering property, stated as a test: before release there is no B.
    function test_bIsAbsentUntilRelease() public {
        PineSignDelivery.SendParams memory p = baseParams;
        vm.prank(alice);
        bytes32 id = delivery.send(p);
        assertEq(delivery.get(id).releasedKey, bytes32(0));

        delivery.markAccepted(id);
        assertEq(delivery.get(id).releasedKey, bytes32(0), "accepting must not release");

        vm.prank(releaser);
        delivery.release(id, B);
        assertEq(delivery.get(id).releasedKey, B);
    }

    function test_onlyTheReleaserMayRelease() public {
        bytes32 id = accepted();
        vm.prank(alice); // the sender, who nominated someone else
        vm.expectRevert(PineSignDelivery.NotReleaser.selector);
        delivery.release(id, B);
    }

    /// The releaser cannot post a different half and call it delivered.
    function test_aWrongReleaseKeyIsRefused() public {
        bytes32 id = accepted();
        vm.prank(releaser);
        vm.expectRevert(PineSignDelivery.BadReleaseKey.selector);
        delivery.release(id, keccak256("not B"));
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Accepted));
    }

    function test_releaseIsOnlyOnce() public {
        bytes32 id = accepted();
        vm.prank(releaser);
        delivery.release(id, B);
        vm.prank(releaser);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.Released)
        );
        delivery.release(id, B);
    }

    function test_releaseAfterItsWindowIsRefused() public {
        bytes32 id = accepted();
        vm.warp(releaseBy + 1);
        vm.prank(releaser);
        vm.expectRevert(PineSignDelivery.ReleaseWindowClosed.selector);
        delivery.release(id, B);
    }

    // ---- the sender defaulting ----

    /**
     * The asymmetry this protocol cannot remove, on the record.
     *
     * The recipient signs before `B` exists, so a releaser who never releases
     * leaves an acceptance on chain with nothing delivered against it. The
     * contract cannot force a release — but it can make the default provable,
     * which is the difference between a bad outcome and a deniable one.
     */
    function test_aReleaserWhoNeverReleasesIsOnRecord() public {
        bytes32 id = accepted();
        vm.warp(releaseBy + 1);
        delivery.expire(id);

        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Expired));
        assertTrue(delivery.senderDefaulted(id), "an accepted, unreleased, lapsed transfer is a default");
    }

    function test_aCompletedDeliveryIsNotADefault() public {
        bytes32 id = accepted();
        vm.prank(releaser);
        delivery.release(id, B);
        vm.warp(releaseBy + 1);
        assertFalse(delivery.senderDefaulted(id));
    }

    function test_aReleasedDeliveryCannotLapse() public {
        bytes32 id = accepted();
        vm.prank(releaser);
        delivery.release(id, B);
        vm.warp(releaseBy + 1);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.Released)
        );
        delivery.expire(id);
    }

    function test_anAcceptedTransferCannotLapseEarly() public {
        bytes32 id = accepted();
        vm.warp(acceptBy + 1); // past accept, still inside the release window
        vm.expectRevert(PineSignDelivery.StillInTime.selector);
        delivery.expire(id);
    }

    function test_theSenderCannotAbortAfterAcceptance() public {
        bytes32 id = accepted();
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.Accepted)
        );
        delivery.abortSend(id);
    }

    function test_acceptingTwiceIsRefused() public {
        bytes32 id = accepted();
        bytes memory authData = new bytes(37);
        authData[32] = 0x05;
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.Accepted)
        );
        delivery.accept(
            id,
            WebAuthn.Assertion({
                authenticatorData: authData,
                clientDataJSON: bytes('{"type":"webauthn.get"}'),
                typeIndex: 1,
                challengeIndex: 0,
                originIndex: 0,
                r: bytes32(uint256(1)),
                s: bytes32(uint256(2))
            })
        );
    }
}

/**
 * The origin allow-list, which is a deployment property and not a per-transfer
 * one — because a sender who could nominate it could have an "acceptance"
 * signed on a page of their own choosing.
 */
contract PineSignDeliveryOriginTest is Test {
    /// In storage rather than `constant`: see the note in the first suite.
    bytes32 rpIdHash = sha256("id.example.com");
    bytes32 constant ALLOWED = keccak256("https://v1.id.example.com");
    bytes32 constant ALSO_ALLOWED = keccak256("https://v2.id.example.com");

    function deploy() internal returns (PineSignDelivery) {
        bytes32[] memory origins = new bytes32[](2);
        origins[0] = ALLOWED;
        origins[1] = ALSO_ALLOWED;
        return new PineSignDelivery(rpIdHash, origins);
    }

    function test_theAllowedOriginsAreTheOnesGivenAtDeployment() public {
        PineSignDelivery d = deploy();
        assertTrue(d.allowedOrigin(ALLOWED));
        assertTrue(d.allowedOrigin(ALSO_ALLOWED), "several published versions coexist");
        assertFalse(d.allowedOrigin(keccak256("https://evil.example")));
        assertFalse(d.allowedOrigin(bytes32(0)), "zero must never be allowed");
    }

    function test_theRpIdIsImmutable() public {
        assertEq(deploy().rpIdHash(), rpIdHash);
    }

    /// expectRevert needs the revert to happen below the test's own frame, so
    /// deployment goes through an external call.
    function deployWith(bytes32 rpId, bytes32[] memory origins) external returns (address) {
        return address(new PineSignDelivery(rpId, origins));
    }

    function test_aDeploymentNeedsAnRpId() public {
        bytes32[] memory origins = new bytes32[](1);
        origins[0] = ALLOWED;
        vm.expectRevert(PineSignDelivery.EmptyField.selector);
        this.deployWith(bytes32(0), origins);
    }

    function test_aDeploymentNeedsAtLeastOneOrigin() public {
        bytes32[] memory none = new bytes32[](0);
        vm.expectRevert(PineSignDelivery.EmptyField.selector);
        this.deployWith(rpIdHash, none);
    }

    function test_aZeroOriginIsRefusedAtDeployment() public {
        bytes32[] memory zeroed = new bytes32[](1);
        vm.expectRevert(PineSignDelivery.EmptyField.selector);
        this.deployWith(rpIdHash, zeroed);
    }

    /// An assertion whose origin is not on the list never reaches the signature
    /// check, so the error says which thing was wrong.
    function test_anUnlistedOriginIsRefusedBeforeVerifying() public {
        PineSignDelivery d = deploy();

        PineSignDelivery.SendParams memory p = PineSignDelivery.SendParams({
            releaser: address(this),
            passkeyX: bytes32(uint256(0x1111)),
            passkeyY: bytes32(uint256(0x2222)),
            pkBX: bytes32(uint256(0x3333)),
            pkBOdd: false,
            ephemeralX: bytes32(uint256(0x4444)),
            ephemeralOdd: true,
            swarmRef: keccak256("swarm"),
            ciphertextHash: keccak256("C"),
            plaintextCommitment: keccak256(abi.encode(keccak256("salt||F"))),
            releaseCommitment: keccak256(abi.encode(bytes32(uint256(7)))),
            descriptionHash: keccak256("d"),
            acceptBy: uint64(block.timestamp + 1 days),
            releaseBy: uint64(block.timestamp + 2 days)
        });
        bytes32 id = d.send(p);

        bytes memory authData = new bytes(37);
        authData[32] = 0x05;
        bytes memory json = bytes('{"type":"webauthn.get","challenge":"","origin":"https://evil.example"}');

        vm.expectRevert(PineSignDelivery.OriginNotAllowed.selector);
        d.accept(
            id,
            WebAuthn.Assertion({
                authenticatorData: authData,
                clientDataJSON: json,
                typeIndex: 1,
                challengeIndex: 23,
                originIndex: 38,
                r: bytes32(uint256(1)),
                s: bytes32(uint256(2))
            })
        );
    }

    /// A wrong originIndex reads nothing and must fail closed, not open.
    function test_aWrongOriginIndexFailsClosed() public {
        bytes memory json = bytes('{"type":"webauthn.get","origin":"https://v1.id.example.com"}');
        WebAuthn.Assertion memory a = WebAuthn.Assertion({
            authenticatorData: new bytes(37),
            clientDataJSON: json,
            typeIndex: 1,
            challengeIndex: 0,
            originIndex: 999,
            r: bytes32(0),
            s: bytes32(0)
        });
        assertEq(WebAuthn.originHashOf(a), bytes32(0));
    }
}

/**
 * What the recipient's signature says, and that it cannot be made to say
 * something else afterwards.
 *
 * The id does not cover `releaseCommitment`, so the digest has to — otherwise
 * an acceptance would not name the key half it was given in exchange for.
 */
contract PineSignDeliveryDigestTest is Test {
    DeliveryHarness delivery;
    address alice = address(0xA11CE);
    address releaser = address(0xBEEF);
    bytes32 constant B = keccak256("the half the sender holds back");
    bytes32 rpIdHash = sha256("id.example.com");
    bytes32 constant ORIGIN_HASH = keccak256("https://v1.id.example.com");
    PineSignDelivery.SendParams baseParams;

    function setUp() public {
        bytes32[] memory origins = new bytes32[](1);
        origins[0] = ORIGIN_HASH;
        delivery = new DeliveryHarness(rpIdHash, origins);
        vm.warp(1_700_000_000);
        baseParams = PineSignDelivery.SendParams({
            releaser: releaser,
            passkeyX: bytes32(uint256(0x1111)),
            passkeyY: bytes32(uint256(0x2222)),
            pkBX: bytes32(uint256(0x3333)),
            pkBOdd: false,
            ephemeralX: bytes32(uint256(0x4444)),
            ephemeralOdd: true,
            swarmRef: keccak256("swarm"),
            ciphertextHash: keccak256("C"),
            plaintextCommitment: keccak256(abi.encode(keccak256("salt||F"))),
            releaseCommitment: keccak256(abi.encode(B)),
            descriptionHash: keccak256("an invoice"),
            acceptBy: uint64(block.timestamp + 1 days),
            releaseBy: uint64(block.timestamp + 2 days)
        });
    }

    function sendWith(PineSignDelivery.SendParams memory p) internal returns (bytes32) {
        vm.prank(alice);
        return delivery.send(p);
    }

    /**
     * Two transfers identical but for the committed key half share an id —
     * that is the consequence of taking releaseCommitment out of it — and must
     * therefore produce different digests, or a signature for one would be a
     * signature for the other.
     */
    function test_theDigestSeparatesTransfersTheIdCannot() public {
        PineSignDelivery.SendParams memory first = baseParams;
        bytes32 id1 = sendWith(first);
        bytes32 digest1 = delivery.acceptDigest(id1);

        PineSignDelivery.SendParams memory second = baseParams;
        second.releaseCommitment = keccak256(abi.encode(keccak256("a different half")));
        assertEq(delivery.transferId(alice, second), id1, "the id cannot tell these apart");

        // The same id is already taken, so this is the proof that matters:
        // the digest is a function of the committed half, not just the id.
        DeliveryHarness other = new DeliveryHarness(rpIdHash, originList());
        vm.prank(alice);
        bytes32 id2 = other.send(second);
        assertEq(id2, id1, "same id on a fresh deployment");
        assertTrue(other.acceptDigest(id2) != digest1, "the digest must differ");
    }

    function originList() internal pure returns (bytes32[] memory origins) {
        origins = new bytes32[](1);
        origins[0] = ORIGIN_HASH;
    }

    function test_theDigestCoversTheSwarmReference() public {
        bytes32 digest = delivery.acceptDigest(sendWith(baseParams));
        PineSignDelivery.SendParams memory moved = baseParams;
        moved.swarmRef = keccak256("somewhere else");
        DeliveryHarness other = new DeliveryHarness(rpIdHash, originList());
        vm.prank(alice);
        assertTrue(other.acceptDigest(other.send(moved)) != digest);
    }

    function test_theDigestCoversTheReleaser() public {
        bytes32 digest = delivery.acceptDigest(sendWith(baseParams));
        PineSignDelivery.SendParams memory swapped = baseParams;
        swapped.releaser = address(0xC0FFEE);
        DeliveryHarness other = new DeliveryHarness(rpIdHash, originList());
        vm.prank(alice);
        assertTrue(other.acceptDigest(other.send(swapped)) != digest);
    }

    /**
     * Nothing the recipient signed over can change afterwards.
     *
     * Read before, read again after an acceptance and after a release. The
     * contract has no setter for any of these, and this is the test that would
     * notice if one were ever added.
     */
    function test_nothingSignedOverCanChangeAfterSend() public {
        bytes32 id = sendWith(baseParams);
        bytes32 digest = delivery.acceptDigest(id);
        PineSignDelivery.Delivery memory before = delivery.get(id);

        delivery.markAccepted(id);
        assertEq(delivery.acceptDigest(id), digest, "accepting changed the digest");

        vm.prank(releaser);
        delivery.release(id, B);
        assertEq(delivery.acceptDigest(id), digest, "releasing changed the digest");

        PineSignDelivery.Delivery memory now_ = delivery.get(id);
        assertEq(now_.releaseCommitment, before.releaseCommitment);
        assertEq(now_.ciphertextHash, before.ciphertextHash);
        assertEq(now_.plaintextCommitment, before.plaintextCommitment);
        assertEq(now_.descriptionHash, before.descriptionHash);
        assertEq(now_.swarmRef, before.swarmRef);
        assertEq(now_.releaser, before.releaser);
        assertEq(now_.acceptBy, before.acceptBy);
        assertEq(now_.passkeyX, before.passkeyX);
        assertEq(now_.passkeyY, before.passkeyY);
    }

    /// And the released half is the one that was committed to, not another.
    function test_theReleasedHalfIsTheCommittedOne() public {
        bytes32 id = sendWith(baseParams);
        delivery.markAccepted(id);
        vm.prank(releaser);
        delivery.release(id, B);
        PineSignDelivery.Delivery memory d = delivery.get(id);
        assertEq(keccak256(abi.encode(d.releasedKey)), d.releaseCommitment);
    }
}

/**
 * Releasing without a funded wallet.
 *
 * The default releaser is the sender, whose key is derived from their passkey
 * and has no ether. So the signature path is not a convenience — it is what
 * makes the stated default possible at all.
 */
contract PineSignDeliveryReleaseSignedTest is Test {
    DeliveryHarness delivery;

    uint256 aliceKey = 0xA11CE;
    address alice;
    address relayer = address(0xDEAD);
    bytes32 constant B = keccak256("the half the sender holds back");
    bytes32 rpIdHash = sha256("id.example.com");
    bytes32 constant ORIGIN_HASH = keccak256("https://v1.id.example.com");
    PineSignDelivery.SendParams baseParams;
    bytes32 id;

    function setUp() public {
        alice = vm.addr(aliceKey);
        bytes32[] memory origins = new bytes32[](1);
        origins[0] = ORIGIN_HASH;
        delivery = new DeliveryHarness(rpIdHash, origins);
        vm.warp(1_700_000_000);
        baseParams = PineSignDelivery.SendParams({
            releaser: alice, // the sender releases, which is the default
            passkeyX: bytes32(uint256(0x1111)),
            passkeyY: bytes32(uint256(0x2222)),
            pkBX: bytes32(uint256(0x3333)),
            pkBOdd: false,
            ephemeralX: bytes32(uint256(0x4444)),
            ephemeralOdd: true,
            swarmRef: keccak256("swarm"),
            ciphertextHash: keccak256("C"),
            plaintextCommitment: keccak256(abi.encode(keccak256("salt||F"))),
            releaseCommitment: keccak256(abi.encode(B)),
            descriptionHash: keccak256("an invoice"),
            acceptBy: uint64(block.timestamp + 1 days),
            releaseBy: uint64(block.timestamp + 2 days)
        });
        PineSignDelivery.SendParams memory p = baseParams;
        vm.prank(alice);
        id = delivery.send(p);
        delivery.markAccepted(id);
    }

    function sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_anyoneMayCarryTheReleasersSignature() public {
        bytes memory signature = sign(aliceKey, delivery.releaseDigest(id, B));

        // Alice holds no ether and never submits anything herself.
        vm.prank(relayer);
        delivery.releaseSigned(id, B, signature);

        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Released));
        assertEq(delivery.get(id).releasedKey, B);
    }

    function test_aRelayerCannotChangeWhichHalfIsReleased() public {
        bytes memory signature = sign(aliceKey, delivery.releaseDigest(id, B));
        vm.prank(relayer);
        vm.expectRevert(PineSignDelivery.NotReleaser.selector);
        // A different half means a different digest, so the signature recovers
        // to somebody who is not the releaser.
        delivery.releaseSigned(id, keccak256("another half"), signature);
    }

    function test_somebodyElsesSignatureIsRefused() public {
        bytes memory signature = sign(0xB0B, delivery.releaseDigest(id, B));
        vm.expectRevert(PineSignDelivery.NotReleaser.selector);
        delivery.releaseSigned(id, B, signature);
    }

    function test_aSignatureForAnotherTransferIsRefused() public {
        bytes memory signature = sign(aliceKey, delivery.releaseDigest(keccak256("elsewhere"), B));
        vm.expectRevert(PineSignDelivery.NotReleaser.selector);
        delivery.releaseSigned(id, B, signature);
    }

    /// The digest is chain- and contract-bound, so an authorisation cannot be
    /// lifted from a testnet or from another deployment.
    function test_theReleaseDigestIsBoundToTheChain() public {
        bytes32 digest = delivery.releaseDigest(id, B);
        vm.chainId(block.chainid + 1);
        assertTrue(delivery.releaseDigest(id, B) != digest);
    }

    function test_releasingTwiceHasNowhereToLand() public {
        bytes memory signature = sign(aliceKey, delivery.releaseDigest(id, B));
        delivery.releaseSigned(id, B, signature);
        vm.expectRevert(
            abi.encodeWithSelector(PineSignDelivery.WrongState.selector, PineSignDelivery.State.Released)
        );
        delivery.releaseSigned(id, B, signature);
    }

    function test_aMalformedSignatureIsRefused() public {
        vm.expectRevert(PineSignDelivery.BadSignature.selector);
        delivery.releaseSigned(id, B, hex"1234");
    }

    function test_aZeroSignatureIsRefused() public {
        vm.expectRevert(PineSignDelivery.BadSignature.selector);
        delivery.releaseSigned(id, B, new bytes(65));
    }

    /// The other encoding of the same signature is refused rather than treated
    /// as a second valid authorisation.
    function test_aHighSSignatureIsRefused() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, delivery.releaseDigest(id, B));
        uint256 flipped =
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s);
        vm.expectRevert(PineSignDelivery.BadSignature.selector);
        delivery.releaseSigned(id, B, abi.encodePacked(r, bytes32(flipped), v == 27 ? 28 : 27));
    }

    /// And the funded path still works, for a releaser who does hold ether.
    function test_aFundedReleaserCanStillCallDirectly() public {
        vm.prank(alice);
        delivery.release(id, B);
        assertEq(uint256(delivery.stateOf(id)), uint256(PineSignDelivery.State.Released));
    }
}
