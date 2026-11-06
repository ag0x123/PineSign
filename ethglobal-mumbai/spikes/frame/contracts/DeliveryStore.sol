// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Spike 5e: what an execute frame writes so a reader can fetch it later.
///
/// Deliberately plain storage with no access control: the point of the spike is that a SENDER frame can write
/// it and any reader can get it back, not who is allowed to.
contract DeliveryStore {
    struct Delivery {
        bytes encryptedKey;
        uint64 blockNumber;
    }

    mapping(bytes32 => Delivery) internal deliveries;

    event Stored(bytes32 indexed acceptHash, uint256 keyLength);

    function store(bytes32 acceptHash, bytes calldata encryptedKey) external {
        deliveries[acceptHash] = Delivery(encryptedKey, uint64(block.number));
        emit Stored(acceptHash, encryptedKey.length);
    }

    function get(bytes32 acceptHash) external view returns (bytes memory encryptedKey, uint64 blockNumber) {
        Delivery storage d = deliveries[acceptHash];
        return (d.encryptedKey, d.blockNumber);
    }
}
