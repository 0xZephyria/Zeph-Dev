// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ExampleToken is ERC20 {
    using SafeMath for uint256;

    address public owner;
    mapping(address => bool) public minters;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function safeTransfer(address to, uint256 amount) external returns (bool) {
        uint256 balance = balanceOf(msg.sender);
        require(balance >= amount, "Insufficient");
        uint256 newBalance = balance.sub(amount);
        return transfer(to, amount);
    }
}
