// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IPair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 ts);
}

/// A small lending market with the mistakes that cost real protocols real money.
contract VulnerableLending {
    IERC20 public collateralToken;
    IERC20 public stable;
    IPair public pair;
    address public owner;
    address public priceFeed;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public ethDeposits;

    uint256 public constant LTV = 75;

    constructor(IERC20 _collateral, IERC20 _stable, IPair _pair) {
        collateralToken = _collateral;
        stable = _stable;
        pair = _pair;
        owner = msg.sender;
    }

    // price of collateral in stable, straight from the AMM reserves
    function collateralPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    function deposit(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 value = collateral[msg.sender] * collateralPrice() / 1e18;
        require(debt[msg.sender] + amount <= value * LTV / 100, "undercollateralised");
        debt[msg.sender] += amount;
        stable.transfer(msg.sender, amount);
    }

    function depositEth() external payable {
        ethDeposits[msg.sender] += msg.value;
    }

    function withdrawEth(uint256 amount) external {
        require(ethDeposits[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        ethDeposits[msg.sender] -= amount;
    }

    function setPriceFeed(address feed) external {
        priceFeed = feed;
    }

    function emergencyWithdraw(address to) external {
        require(tx.origin == owner, "not owner");
        stable.transfer(to, stable.balanceOf(address(this)));
    }

    function refund(address payable user, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        user.send(amount);
    }
}
