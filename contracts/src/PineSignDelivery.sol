// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WebAuthn} from "./WebAuthn.sol";

/**
 * PineSign delivery: the file cannot be read without the acceptance on chain.
 *
 * The problem with the earlier design
 * -----------------------------------
 * `PineSignReceipts` records that a recipient claimed a file, and a claim
 * requires revealing a preimage only decryption produces. That proves the
 * claim was honest — but nothing forces a claim to happen at all. A recipient
 * who decrypted and then went quiet read the file and left no trace, and the
 * sender's only recourse was to trust the gateway to have refused.
 *
 * What this does instead
 * ----------------------
 * The file's key is split, and one half does not exist publicly until the
 * recipient has accepted on chain.
 *
 *   C  = AEAD(K, salt || F)         the ciphertext, on Swarm, public
 *   K  = A XOR B                    the key, which nobody holds whole
 *   A  = HKDF(ECDH(e_A, pk_B), id)  only the recipient can derive this
 *   B                               random, held back by the sender
 *
 * The sender publishes `C` and `keccak(B)`, and nothing else. The recipient
 * can compute `A` the moment the transfer exists, and `A` alone decrypts
 * nothing. `B` reaches the chain only after `accept`, which is a passkey
 * signature this contract verifies itself.
 *
 * So the ordering is not a policy anyone enforces. It is arithmetic: no
 * acceptance, no `B`; no `B`, no `K`; no `K`, no plaintext.
 *
 * What this proves, and what it does not
 * --------------------------------------
 * `accept` means a passkey was tapped on an allow-listed PineSign page for
 * this exact transfer. It does **not** mean the recipient has read the file,
 * because the recipient signs before `B` exists — this is registered post: you
 * sign for the envelope. And it does not prove the file was what the sender
 * said it was; `plaintextCommitment` lets the recipient *detect* a junk file
 * after release, but by then they have accepted, and their remedy is off chain.
 *
 * Both of those are stated plainly because the contract cannot fix them, and a
 * reader deserves to know which claims it does carry.
 *
 * No owner, no upgrade path, no admin key.
 */
contract PineSignDelivery {
    enum State {
        None,
        Sent,
        Accepted,
        Released,
        Expired,
        SenderAborted
    }

    /**
     * Field order here is storage layout, not taste.
     *
     * The address, the two parity bits and the state share one slot; the four
     * timestamps share another. Each `bytes32` needs its own regardless, and
     * those are the irreducible cost of a delivery: eleven commitments that
     * anyone must be able to re-derive.
     */
    struct Delivery {
        address sender;
        /// Compressed secp256k1 keys are x plus a parity bit; the bits live
        /// here so they cost nothing of their own.
        bool pkBOdd;
        bool ephemeralOdd;
        State state;
        /// Who may post `B`. The sender by default, but deliberately separable:
        /// whoever serves the signing page should not also be able to release.
        address releaser;
        uint64 acceptBy;
        uint64 releaseBy;
        uint64 acceptedAt;
        uint64 releasedAt;
        /// The recipient's passkey, frozen at send. Only this credential can
        /// accept, and it is the same key the gateway recorded at sign-up.
        bytes32 passkeyX;
        bytes32 passkeyY;
        /// The recipient's encryption key, and this transfer's ephemeral key.
        bytes32 pkBX;
        bytes32 ephemeralX;
        bytes32 swarmRef;
        /// keccak(C) — so the recipient can check the ciphertext is the one
        /// committed to before accepting anything.
        bytes32 ciphertextHash;
        /// keccak(keccak(salt || F)) — detects a junk file after release.
        bytes32 plaintextCommitment;
        /// keccak(B) — what `release` is checked against.
        bytes32 releaseCommitment;
        /// Hash of the short description, which lives encrypted on Swarm.
        bytes32 descriptionHash;
        /// B, once it is public. This is the thing the recipient was waiting for.
        bytes32 releasedKey;
    }

    struct SendParams {
        address releaser;
        bytes32 passkeyX;
        bytes32 passkeyY;
        bytes32 pkBX;
        bool pkBOdd;
        bytes32 ephemeralX;
        bool ephemeralOdd;
        bytes32 swarmRef;
        bytes32 ciphertextHash;
        bytes32 plaintextCommitment;
        bytes32 releaseCommitment;
        bytes32 descriptionHash;
        uint64 acceptBy;
        uint64 releaseBy;
    }

    /**
     * Where an acceptance may be signed. Fixed at deployment, not per transfer.
     *
     * These were once part of `SendParams`, which was a mistake worth naming:
     * it let a sender nominate the relying party and origin their recipient's
     * passkey would be checked against. A sender who controlled a page could
     * therefore have had an "acceptance" signed somewhere of their choosing.
     * They belong to the deployment, so they live here, immutable, and a new
     * signing-page origin means a new contract — which is the same rule the
     * published page versions already follow.
     */
    bytes32 public immutable rpIdHash;

    mapping(bytes32 => bool) public allowedOrigin;

    constructor(bytes32 rpIdHash_, bytes32[] memory originHashes) {
        if (rpIdHash_ == bytes32(0) || originHashes.length == 0) revert EmptyField();
        rpIdHash = rpIdHash_;
        for (uint256 i = 0; i < originHashes.length; i++) {
            if (originHashes[i] == bytes32(0)) revert EmptyField();
            allowedOrigin[originHashes[i]] = true;
        }
    }

    /// Internal rather than private so a test harness can stand in for the one
    /// step this toolchain cannot execute: a verifying P-256 assertion.
    mapping(bytes32 => Delivery) internal _deliveries;

    /**
     * Ephemeral keys, once used.
     *
     * `A` is derived from the ephemeral key and the recipient's key, so reusing
     * an ephemeral key across two transfers to the same recipient would give
     * both the same `A`. Then releasing `B` for one would be releasing most of
     * the key for the other. Refused here rather than left to the sender to
     * remember.
     */
    mapping(bytes32 => bool) public ephemeralUsed;

    // EIP-712. The struct name is this protocol's own, so a signature gathered
    // here cannot be replayed into some other contract's `Accept`.
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ACCEPT_TYPEHASH =
        keccak256(
            "PineSignAccept(bytes32 transferId,bytes32 ciphertextHash,bytes32 plaintextCommitment,bytes32 descriptionHash,uint64 acceptBy)"
        );
    bytes32 private constant NAME_HASH = keccak256("PineSign");
    bytes32 private constant VERSION_HASH = keccak256("1");

    event Sent(bytes32 indexed id, address indexed sender, bytes32 swarmRef, uint64 acceptBy);
    event Accepted(bytes32 indexed id, bytes32 passkeyX, uint64 at);
    event Released(bytes32 indexed id, bytes32 releasedKey, uint64 at);
    event Aborted(bytes32 indexed id, uint64 at);
    event Lapsed(bytes32 indexed id, State from, uint64 at);

    error AlreadySent();
    error UnknownTransfer();
    error WrongState(State actual);
    error EphemeralReused();
    error DeadlinesOutOfOrder();
    error AcceptWindowClosed();
    error ReleaseWindowClosed();
    error StillInTime();
    error NotReleaser();
    error NotSender();
    error BadAssertion();
    error BadReleaseKey();
    error EmptyField();
    error OriginNotAllowed();

    /**
     * The id is derived from the transfer, never chosen — so no field can be
     * swapped afterwards and no id can be squatted by someone who cannot
     * construct it.
     */
    function transferId(address sender, SendParams memory p) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                sender,
                p.passkeyX,
                p.passkeyY,
                p.pkBX,
                p.pkBOdd,
                p.ephemeralX,
                p.ephemeralOdd,
                p.ciphertextHash,
                p.plaintextCommitment,
                p.releaseCommitment,
                p.descriptionHash,
                p.acceptBy,
                p.releaseBy
            )
        );
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// The digest the recipient's passkey signs. Also the WebAuthn challenge.
    function acceptDigest(bytes32 id) public view returns (bytes32) {
        Delivery storage d = _deliveries[id];
        if (d.state == State.None) revert UnknownTransfer();
        bytes32 structHash = keccak256(
            abi.encode(
                ACCEPT_TYPEHASH, id, d.ciphertextHash, d.plaintextCommitment, d.descriptionHash, d.acceptBy
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function get(bytes32 id) external view returns (Delivery memory) {
        return _deliveries[id];
    }

    function stateOf(bytes32 id) external view returns (State) {
        return _deliveries[id].state;
    }

    // ---- the transitions ----

    function send(SendParams calldata p) external returns (bytes32 id) {
        if (p.acceptBy <= block.timestamp) revert AcceptWindowClosed();
        if (p.releaseBy <= p.acceptBy) revert DeadlinesOutOfOrder();
        // A zero commitment would make `release` or the junk check vacuous.
        if (p.releaseCommitment == bytes32(0) || p.ciphertextHash == bytes32(0)) revert EmptyField();
        if (p.passkeyX == bytes32(0) && p.passkeyY == bytes32(0)) revert EmptyField();

        bytes32 ephemeral = keccak256(abi.encode(p.ephemeralX, p.ephemeralOdd));
        if (ephemeralUsed[ephemeral]) revert EphemeralReused();

        id = transferId(msg.sender, p);
        if (_deliveries[id].state != State.None) revert AlreadySent();

        ephemeralUsed[ephemeral] = true;

        Delivery storage d = _deliveries[id];
        d.sender = msg.sender;
        d.releaser = p.releaser == address(0) ? msg.sender : p.releaser;
        d.passkeyX = p.passkeyX;
        d.passkeyY = p.passkeyY;
        d.pkBX = p.pkBX;
        d.pkBOdd = p.pkBOdd;
        d.ephemeralX = p.ephemeralX;
        d.ephemeralOdd = p.ephemeralOdd;
        d.swarmRef = p.swarmRef;
        d.ciphertextHash = p.ciphertextHash;
        d.plaintextCommitment = p.plaintextCommitment;
        d.releaseCommitment = p.releaseCommitment;
        d.descriptionHash = p.descriptionHash;
        d.acceptBy = p.acceptBy;
        d.releaseBy = p.releaseBy;
        d.state = State.Sent;

        emit Sent(id, msg.sender, p.swarmRef, p.acceptBy);
    }

    /**
     * The recipient accepts, with their passkey.
     *
     * Relayed: anyone may submit this, and the gateway normally does, because
     * the recipient has no funded account and should not need one. That is
     * safe because the signature is over this transfer's own digest and is
     * checked here — a relayer can choose whether to submit, never what.
     *
     * The state and timing checks come before the signature check. They are
     * far cheaper, and it means a caller learns *which* thing was wrong
     * instead of being told only that verification failed.
     */
    function accept(bytes32 id, WebAuthn.Assertion calldata assertion) external {
        Delivery storage d = _deliveries[id];
        if (d.state == State.None) revert UnknownTransfer();
        if (d.state != State.Sent) revert WrongState(d.state);
        if (block.timestamp > d.acceptBy) revert AcceptWindowClosed();

        // The origin the ceremony claims must be one this deployment allows,
        // and the caller says where to find it in clientDataJSON. Reading it
        // out and checking the set is what stops a page nobody published from
        // producing an acceptance.
        bytes32 claimedOrigin = WebAuthn.originHashOf(assertion);
        if (!allowedOrigin[claimedOrigin]) revert OriginNotAllowed();

        if (
            !WebAuthn.verify(
                assertion, acceptDigest(id), rpIdHash, claimedOrigin, d.passkeyX, d.passkeyY
            )
        ) revert BadAssertion();

        d.state = State.Accepted;
        d.acceptedAt = uint64(block.timestamp);

        emit Accepted(id, d.passkeyX, d.acceptedAt);
    }

    /**
     * The releaser posts `B`, and the recipient can finally decrypt.
     *
     * Checked against `keccak(B)` committed at send, so the releaser cannot
     * post a different half and claim to have delivered.
     */
    function release(bytes32 id, bytes32 b) external {
        Delivery storage d = _deliveries[id];
        if (d.state == State.None) revert UnknownTransfer();
        if (d.state != State.Accepted) revert WrongState(d.state);
        if (msg.sender != d.releaser) revert NotReleaser();
        if (block.timestamp > d.releaseBy) revert ReleaseWindowClosed();
        if (keccak256(abi.encode(b)) != d.releaseCommitment) revert BadReleaseKey();

        d.state = State.Released;
        d.releasedKey = b;
        d.releasedAt = uint64(block.timestamp);

        emit Released(id, b, d.releasedAt);
    }

    /// The sender changes their mind, before anyone has accepted.
    function abortSend(bytes32 id) external {
        Delivery storage d = _deliveries[id];
        if (d.state == State.None) revert UnknownTransfer();
        if (d.state != State.Sent) revert WrongState(d.state);
        if (msg.sender != d.sender) revert NotSender();

        d.state = State.SenderAborted;
        emit Aborted(id, uint64(block.timestamp));
    }

    /**
     * Mark a lapsed transfer, from either side of the exchange.
     *
     * Two different failures end up here, and the state records which. Nobody
     * accepted before `acceptBy`: the offer simply expired. Somebody accepted
     * and the releaser never released before `releaseBy`: the recipient signed
     * for an envelope that never arrived, and this is the trace of it — which
     * is the only reason this function needs to exist. An accepted-but-never-
     * released delivery that quietly vanished would leave the recipient's
     * signature on chain with nothing to say the sender defaulted.
     *
     * Callable by anyone, because both parties have a reason to want it on the
     * record and neither should depend on the other to do it.
     */
    function expire(bytes32 id) external {
        Delivery storage d = _deliveries[id];
        if (d.state == State.None) revert UnknownTransfer();

        if (d.state == State.Sent) {
            if (block.timestamp <= d.acceptBy) revert StillInTime();
        } else if (d.state == State.Accepted) {
            if (block.timestamp <= d.releaseBy) revert StillInTime();
        } else {
            revert WrongState(d.state);
        }

        State from = d.state;
        d.state = State.Expired;
        emit Lapsed(id, from, uint64(block.timestamp));
    }

    /// Did the releaser default after an acceptance? The sender's failure, on record.
    function senderDefaulted(bytes32 id) external view returns (bool) {
        Delivery storage d = _deliveries[id];
        return d.state == State.Expired && d.acceptedAt != 0 && d.releasedAt == 0;
    }

    function isReleased(bytes32 id) external view returns (bool) {
        return _deliveries[id].state == State.Released;
    }
}
