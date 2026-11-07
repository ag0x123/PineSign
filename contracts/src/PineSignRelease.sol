// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// What the execute frame of a delivery writes, and what Bob reads to open his file.
///
/// Three things land here together, in one transaction that only happens if Bob's reply verified:
/// the hash of the accept that authorised it, the file's Swarm reference, and the file key sealed
/// to Bob's encryption key. Nobody but Bob can use the key, and without this row there is no key
/// at all — which is the whole claim. No proof, no delivery.
///
/// There is no access control and there does not need to be. A row is only reachable by the hash
/// of an accept, the key in it is useless to anyone else, and the frame transaction that writes it
/// has already been through a validation prefix that checked the DKIM signature. Writing a row
/// nobody asked for costs the writer gas and achieves nothing.
contract PineSignRelease {
    struct Release {
        bytes encryptedKey;
        bytes32 swarmRef;
        uint64 blockNumber;
    }

    mapping(bytes32 => Release) internal releases;

    event Released(bytes32 indexed acceptHash, bytes32 swarmRef, uint256 keyLength);

    /// First argument is the accept hash, and it stays first: the account's validation frame finds
    /// it at a fixed offset in this call's data to check that the frame it is approving releases the
    /// delivery the email actually authorised.
    function release(bytes32 acceptHash, bytes calldata encryptedKey, bytes32 swarmRef) external {
        require(releases[acceptHash].blockNumber == 0, "pinesign: already released");
        releases[acceptHash] = Release(encryptedKey, swarmRef, uint64(block.number));
        emit Released(acceptHash, swarmRef, encryptedKey.length);
    }

    function get(bytes32 acceptHash)
        external
        view
        returns (bytes memory encryptedKey, bytes32 swarmRef, uint64 blockNumber)
    {
        Release storage r = releases[acceptHash];
        return (r.encryptedKey, r.swarmRef, r.blockNumber);
    }
}
