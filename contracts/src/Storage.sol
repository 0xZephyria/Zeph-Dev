// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Storage — key-value store contract.
/// Tests: set value, get value, multi-slot access.
contract Storage {
    mapping(uint256 => uint256) private store;
    uint256 public count;

    function set(uint256 key, uint256 value) public {
        if (store[key] == 0 && value != 0) {
            count++;
        }
        store[key] = value;
    }

    function get(uint256 key) public view returns (uint256) {
        return store[key];
    }

    function remove(uint256 key) public {
        if (store[key] != 0) {
            count--;
        }
        store[key] = 0;
    }
}
