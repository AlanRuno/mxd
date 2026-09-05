require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

module.exports = {
  solidity: {
    // 0.8.28 + cancun required by the locked @openzeppelin/contracts 5.6.1, whose
    // Bytes.sol uses the Cancun `mcopy` opcode (BSC supports Cancun since 2024).
    // Contracts already deployed keep their pinned 0.8.24 metadata; this only
    // affects future compiles/deploys.
    version: "0.8.28",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "cancun",
    },
  },
  networks: {
    bscTestnet: {
      url: process.env.BSC_RPC_URL || "https://data-seed-prebsc-1-s1.binance.org:8545/",
      chainId: 97,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
    bscMainnet: {
      // Set BSC_MAINNET_RPC_URL to your own endpoint. The public dataseed default
      // is fine for read-only work; use a keyed provider for deploys.
      url: process.env.BSC_MAINNET_RPC_URL || "https://bsc-dataseed.binance.org/",
      chainId: 56,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      // Reasonable defaults for a one-shot bridge deploy. BSC mainnet typically
      // accepts 3-5 gwei; we leave room for spikes. Hardhat will auto-estimate
      // gasLimit unless we hit the contract size ceiling.
      gasPrice: process.env.BSC_MAINNET_GAS_PRICE
        ? parseInt(process.env.BSC_MAINNET_GAS_PRICE, 10)
        : 5_000_000_000, // 5 gwei
    },
    localhost: {
      url: "http://127.0.0.1:8545",
    },
  },
};
