// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BNBMXD
 * @notice BEP-20 token representing bridged MXD on BNB Chain.
 *         8 decimals to match MXD's native precision (1 MXD = 100,000,000 base units).
 */
contract BNBMXD is ERC20, Ownable {
    uint8 private constant _DECIMALS = 8;
    address public bridge;

    error OnlyBridge();
    error ZeroAddress();

    modifier onlyBridge() {
        if (msg.sender != bridge) revert OnlyBridge();
        _;
    }

    constructor() ERC20("Bridged MXD", "BNBMXD") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }

    /// @notice Set the authorized bridge contract address. Owner-only.
    function setBridge(address _bridge) external onlyOwner {
        if (_bridge == address(0)) revert ZeroAddress();
        bridge = _bridge;
    }

    /// @notice Mint tokens to `to`. Only callable by the bridge contract.
    function mint(address to, uint256 amount) external onlyBridge {
        _mint(to, amount);
    }

    /// @notice Burn tokens from `from`. Only callable by the bridge contract.
    function burn(address from, uint256 amount) external onlyBridge {
        _burn(from, amount);
    }
}
