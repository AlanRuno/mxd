// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title TestBNBMXD
 * @notice BSC TESTNET stand-in for the production BNBMXD on mainnet
 *         (0xdf1f7AdF59a178BA83f6140a4930cf3BEB7b73BF). Production BNBMXD is a
 *         fixed-supply OZ Ownable ERC-20 with no mint/burn/setBridge — same
 *         model here so MXDBridgeV3 behaves identically.
 *
 *         Initial supply is minted to the deployer once in the constructor;
 *         no further minting is possible. The deployer can then `approve()`
 *         the bridge contract and call `deposit()` to drive an E2E smoke test
 *         on testnet (the bridge transferFrom's the deployer's balance straight
 *         to 0x…dEaD).
 *
 *         Decimals: 8 (matches MXD's native 100,000,000 base-unit precision).
 *
 *         NOT INTENDED FOR MAINNET. The production token already exists;
 *         deploying this on mainnet would create a duplicate-but-unauthorized
 *         token. Name + symbol are prefixed with "Test" to make this obvious.
 */
contract TestBNBMXD is ERC20, Ownable {
    uint8 private constant _DECIMALS = 8;

    /**
     * @param initialSupplyBaseUnits Initial token supply in 8-decimal base units
     *                               (e.g. 1_000_000_00000000 = 1,000,000 BNBMXD).
     */
    constructor(uint256 initialSupplyBaseUnits)
        ERC20("Test Bridged MXD", "tBNBMXD")
        Ownable(msg.sender)
    {
        _mint(msg.sender, initialSupplyBaseUnits);
    }

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }
}
