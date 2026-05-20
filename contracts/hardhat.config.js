require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    bscTestnet: {
      url: process.env.BSC_RPC_URL || "https://data-seed-prebsc-1-s1.binance.org:8545/",
      chainId: 97,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
    bscMainnet: {
      // Provide your own BSC mainnet RPC endpoint via BSC_MAINNET_RPC_URL
      // (e.g. NodeReal, QuickNode, Ankr, or your own node). The public free
      // tier at https://bsc-dataseed.binance.org/ works for occasional calls
      // but is rate-limited and not recommended for production deploys.
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
