// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./BNBMXD.sol";

/**
 * @title MXDBridge
 * @notice Bridge contract for BNB Chain ↔ MXD cross-chain transfers.
 *
 *  Deposit flow  (BNB → MXD):
 *    1. User calls deposit(mxdRecipient, amount)
 *    2. Bridge burns BNBMXD tokens from the user
 *    3. Emits Deposit event — oracle picks this up
 *    4. Oracle submits bridge_mint on MXD side
 *
 *  Withdraw flow (MXD → BNB):
 *    1. User burns MXD tokens on MXD chain
 *    2. Oracle detects burn and calls withdraw() with a signature
 *    3. Bridge mints BNBMXD tokens back to the user
 */
contract MXDBridge is Ownable {
    BNBMXD public immutable token;
    uint256 public immutable launchTimestamp;

    uint256 public constant BASE_DAILY_CAP = 100_00000000;     // 100 MXD (8 decimals)
    uint256 public constant DAILY_CAP_INCREMENT = 10_00000000;  // +10 MXD per day

    uint256 public depositCount;
    uint256 public lastDepositDay;
    uint256 public dailyDepositTotal;
    mapping(address => bool) public operators;
    mapping(bytes32 => bool) public processedMxdTxs;

    event Deposit(
        address indexed depositor,
        bytes20 mxdRecipient,
        uint256 amount,
        uint256 depositId,
        uint256 timestamp
    );

    event Withdrawal(
        address indexed recipient,
        bytes32 mxdTxHash,
        uint256 amount,
        uint256 timestamp
    );

    event OperatorAdded(address indexed operator);
    event OperatorRemoved(address indexed operator);

    error NotOperator();
    error AlreadyProcessed();
    error InvalidSignature();
    error ZeroAmount();
    error ZeroAddress();
    error DailyCapExceeded(uint256 attempted, uint256 remaining);

    modifier onlyOperator() {
        if (!operators[msg.sender]) revert NotOperator();
        _;
    }

    constructor(address _token) Ownable(msg.sender) {
        token = BNBMXD(_token);
        launchTimestamp = block.timestamp;
    }

    // ──────────────────── Operator management ────────────────────

    function addOperator(address op) external onlyOwner {
        if (op == address(0)) revert ZeroAddress();
        operators[op] = true;
        emit OperatorAdded(op);
    }

    function removeOperator(address op) external onlyOwner {
        operators[op] = false;
        emit OperatorRemoved(op);
    }

    // ──────────────────── Deposit (BNB → MXD) ────────────────────

    /**
     * @notice Deposit BNBMXD tokens to bridge them to MXD chain.
     * @param mxdRecipient  20-byte MXD address that will receive minted MXD.
     * @param amount        Amount of BNBMXD tokens (8-decimal base units).
     */
    function deposit(bytes20 mxdRecipient, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (mxdRecipient == bytes20(0)) revert ZeroAddress();

        // Daily cap enforcement
        uint256 currentDay = (block.timestamp - launchTimestamp) / 1 days;
        uint256 cap = BASE_DAILY_CAP + (currentDay * DAILY_CAP_INCREMENT);

        if (currentDay != lastDepositDay) {
            lastDepositDay = currentDay;
            dailyDepositTotal = 0;
        }

        uint256 remaining = cap - dailyDepositTotal;
        if (amount > remaining) revert DailyCapExceeded(amount, remaining);
        dailyDepositTotal += amount;

        token.burn(msg.sender, amount);

        uint256 id = depositCount++;
        emit Deposit(msg.sender, mxdRecipient, amount, id, block.timestamp);
    }

    // ──────────────────── Withdraw (MXD → BNB) ───────────────────

    /**
     * @notice Withdraw: oracle proves a burn happened on MXD, bridge mints BNBMXD.
     * @param recipient   BSC address to receive BNBMXD tokens.
     * @param amount      Amount of tokens (8-decimal base units).
     * @param mxdTxHash   SHA-512-truncated hash of the MXD burn transaction.
     * @param signature   ECDSA signature from a registered operator over
     *                    keccak256(abi.encodePacked(recipient, amount, mxdTxHash, block.chainid)).
     */
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 mxdTxHash,
        bytes calldata signature
    ) external {
        if (processedMxdTxs[mxdTxHash]) revert AlreadyProcessed();
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();

        // Verify operator signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(recipient, amount, mxdTxHash, block.chainid)
        );
        bytes32 ethSignedHash = _toEthSignedMessageHash(messageHash);
        address signer = _recover(ethSignedHash, signature);
        if (!operators[signer]) revert InvalidSignature();

        processedMxdTxs[mxdTxHash] = true;
        token.mint(recipient, amount);

        emit Withdrawal(recipient, mxdTxHash, amount, block.timestamp);
    }

    // ──────────────────── Daily cap views ────────────────────────

    function currentDayNumber() public view returns (uint256) {
        return (block.timestamp - launchTimestamp) / 1 days;
    }

    function currentDailyCap() public view returns (uint256) {
        return BASE_DAILY_CAP + (currentDayNumber() * DAILY_CAP_INCREMENT);
    }

    function dailyDepositUsed() public view returns (uint256) {
        if (currentDayNumber() != lastDepositDay) return 0;
        return dailyDepositTotal;
    }

    function dailyDepositRemaining() public view returns (uint256) {
        return currentDailyCap() - dailyDepositUsed();
    }

    // ──────────────────── Internal helpers ────────────────────────

    function _toEthSignedMessageHash(bytes32 hash) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recover(bytes32 hash, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        // Reject malleable signatures (s must be in lower half of secp256k1 order)
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        return ecrecover(hash, v, r, s);
    }
}
