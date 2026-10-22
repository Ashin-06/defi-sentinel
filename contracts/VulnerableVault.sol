// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// Yield vault behind an upgradeable proxy, plus a raffle and a batch helper.
contract VulnerableVault {
    IERC20 public asset;
    address public owner;
    address public implementation;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public credits;

    function initialize(IERC20 _asset, address _owner) external {
        asset = _asset;
        owner = _owner;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        if (totalSupply == 0) {
            shares = assets;
        } else {
            shares = assets * totalSupply / asset.balanceOf(address(this));
        }
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }

    function raffle() external view returns (uint256 winnerIndex) {
        winnerIndex = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }

    function buyCredits(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            credits[users[i]] += msg.value;
        }
    }

    function claimWithSignature(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount));
        require(ecrecover(digest, v, r, s) == owner, "bad signature");
        asset.transfer(msg.sender, amount);
    }

    function fee(uint256 amount) public pure returns (uint256) {
        return amount / 1000 * 3;
    }
}
