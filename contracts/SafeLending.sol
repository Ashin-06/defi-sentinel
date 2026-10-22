// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface ITwapOracle {
    function consult(address token, uint32 secondsAgo) external view returns (uint256 price);
}

/// The same market with the fixes applied: TWAP oracle, checks-effects-interactions,
/// re-entrancy guard, SafeERC20 and owner-only administration.
contract SafeLending is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable collateralToken;
    IERC20 public immutable stable;
    ITwapOracle public oracle;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public ethDeposits;

    uint256 public constant LTV = 75;
    uint32 public constant TWAP_WINDOW = 30 minutes;

    constructor(IERC20 _collateral, IERC20 _stable, ITwapOracle _oracle) Ownable(msg.sender) {
        collateralToken = _collateral;
        stable = _stable;
        oracle = _oracle;
    }

    function collateralPrice() public view returns (uint256) {
        return oracle.consult(address(collateralToken), TWAP_WINDOW);
    }

    function deposit(uint256 amount) external nonReentrant {
        collateral[msg.sender] += amount;
        collateralToken.safeTransferFrom(msg.sender, address(this), amount);
    }

    function borrow(uint256 amount) external nonReentrant {
        uint256 value = collateral[msg.sender] * collateralPrice() / 1e18;
        require(debt[msg.sender] + amount <= value * LTV / 100, "undercollateralised");
        debt[msg.sender] += amount;
        stable.safeTransfer(msg.sender, amount);
    }

    function depositEth() external payable {
        ethDeposits[msg.sender] += msg.value;
    }

    function withdrawEth(uint256 amount) external nonReentrant {
        require(ethDeposits[msg.sender] >= amount, "insufficient");
        ethDeposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function setOracle(ITwapOracle newOracle) external onlyOwner {
        oracle = newOracle;
    }
}
