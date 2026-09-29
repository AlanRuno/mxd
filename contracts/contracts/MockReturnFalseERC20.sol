// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockReturnFalseERC20
 * @notice TEST-ONLY token whose `transfer` returns `false` instead of reverting.
 *         Models the class of ERC-20s for which a raw `IERC20.transfer(...)` call
 *         silently fails. Used to prove that `MXDBridgeV3.recoverToken` reverts
 *         (via SafeERC20) instead of emitting `TokenRecovered` on a no-op transfer.
 *
 *         NOT INTENDED FOR ANY DEPLOYMENT.
 */
contract MockReturnFalseERC20 {
    string public constant name = "Mock Return-False Token";
    string public constant symbol = "mRF";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }

    /// @dev Real transfer used only to seed the bridge with a balance during tests.
    function seed(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    /// @dev Always fails softly: no state change, returns false.
    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}
