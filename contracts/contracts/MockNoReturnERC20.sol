// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockNoReturnERC20
 * @notice TEST-ONLY token whose `transfer` has no return value (USDT-style,
 *         pre-ERC-20-final ABI). A raw `IERC20.transfer(...)` call against such a
 *         token reverts on ABI decoding; `SafeERC20.safeTransfer` handles it.
 *         Used to prove that the `safeTransfer` fix is also a functional
 *         improvement for `MXDBridgeV3.recoverToken`, not only a hardening.
 *
 *         NOT INTENDED FOR ANY DEPLOYMENT.
 */
contract MockNoReturnERC20 {
    string public constant name = "Mock No-Return Token";
    string public constant symbol = "mNR";
    uint8 public constant decimals = 6;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }

    /// @dev No boolean return value, on purpose.
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(allowance[from][msg.sender] >= amount, "allowance");
        require(balanceOf[from] >= amount, "insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
