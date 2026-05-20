// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MXDBridgeV3
 * @notice Third-generation BNB Chain → MXD bridge. One-way only (BSC to MXD).
 *
 *   Changes from MXDBridge:
 *     - `mxdRecipient` is `bytes32` (was `bytes20`) to carry the full addr32 destination
 *       introduced in MXD v6 — fixes audit C5-1. The 32 bytes are the raw addr32 =
 *       SHA-512(algo_id || pubkey)[0..31]; the textual `mx + Base58Check(...)` form and
 *       its version byte / checksum exist only in the wallet UI layer and never reach
 *       this contract.
 *     - `withdraw()` removed. Bridge is one-way by design; no MXD → BNB code path on chain.
 *     - Single-operator + Ownable model replaced with K-of-N EIP-712 admin governance.
 *       Operators add/remove themselves, change threshold, set caps, pause, and recover
 *       stuck non-BNBMXD tokens via K signatures over typed data. No owner role exists.
 *
 *   Token economics: the deployed BNBMXD on BSC has no `mint`/`burn`/`setBridge` — it's a
 *   plain fixed-supply OZ Ownable ERC-20. To remove deposited tokens from circulation we
 *   transferFrom them to the canonical burn address `0x…dEaD` (OZ ERC-20 blocks transfers
 *   to `address(0)` with `ERC20InvalidReceiver`). Effect: total supply is unchanged on
 *   chain but the deposited balance is permanently unrecoverable — BscScan and most
 *   explorers subtract the dEaD balance from circulating supply. The bridge contract
 *   itself never holds BNBMXD; depositors approve, the bridge moves tokens straight to
 *   dEaD in one atomic transfer.
 */
contract MXDBridgeV3 is EIP712 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    string private constant SIGNING_DOMAIN = "MXDBridge";
    string private constant SIGNATURE_VERSION = "3";

    /// @notice Canonical dead-letter address. OZ ERC-20 forbids transfers to address(0);
    /// this is the universally-recognized substitute. Explorers (BscScan etc.) subtract
    /// the balance held here from circulating supply.
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;

    bytes32 public constant ADD_OPERATOR_TYPEHASH =
        keccak256("AddOperator(address operator,bytes32 nonce,uint256 deadline)");
    bytes32 public constant REMOVE_OPERATOR_TYPEHASH =
        keccak256("RemoveOperator(address operator,bytes32 nonce,uint256 deadline)");
    bytes32 public constant SET_THRESHOLD_TYPEHASH =
        keccak256("SetThreshold(uint256 threshold,bytes32 nonce,uint256 deadline)");
    bytes32 public constant UPDATE_DAILY_CAP_TYPEHASH =
        keccak256("UpdateDailyCap(uint256 baseCap,uint256 increment,bytes32 nonce,uint256 deadline)");
    bytes32 public constant PAUSE_TYPEHASH =
        keccak256("Pause(bytes32 nonce,uint256 deadline)");
    bytes32 public constant UNPAUSE_TYPEHASH =
        keccak256("Unpause(bytes32 nonce,uint256 deadline)");
    bytes32 public constant RECOVER_TOKEN_TYPEHASH =
        keccak256("RecoverToken(address tokenAddr,address recipient,uint256 amount,bytes32 nonce,uint256 deadline)");

    IERC20 public immutable token;
    uint256 public immutable launchTimestamp;

    uint256 public baseDailyCap;
    uint256 public dailyCapIncrement;

    uint256 public depositCount;
    uint256 public lastDepositDay;
    uint256 public dailyDepositTotal;

    address[] private _operatorList;
    mapping(address => bool) public isOperator;
    uint256 public threshold;

    bool public paused;

    mapping(bytes32 => bool) public usedNonces;

    event Deposit(
        address indexed depositor,
        bytes32 indexed mxdRecipient,
        uint256 amount,
        uint256 depositId,
        uint256 timestamp
    );
    event Paused(bytes32 indexed nonce);
    event Unpaused(bytes32 indexed nonce);
    event OperatorAdded(address indexed operator, bytes32 indexed nonce);
    event OperatorRemoved(address indexed operator, bytes32 indexed nonce);
    event ThresholdUpdated(uint256 newThreshold, bytes32 indexed nonce);
    event DailyCapUpdated(uint256 baseCap, uint256 increment, bytes32 indexed nonce);
    event TokenRecovered(address indexed tokenAddr, address indexed to, uint256 amount, bytes32 indexed nonce);

    error ZeroAmount();
    error ZeroAddress();
    error BridgePaused();
    error BridgeNotPaused();
    error DailyCapExceeded(uint256 attempted, uint256 remaining);
    error InvalidThreshold();
    error NotOperator();
    error AlreadyOperator(address operator);
    error DuplicateSigner(address signer);
    error InvalidSignature();
    error InsufficientSignatures(uint256 got, uint256 needed);
    error NonceAlreadyUsed(bytes32 nonce);
    error DeadlineExpired(uint256 deadline);
    error CannotRecoverBridgeToken();
    error EmptyOperatorSet();
    error CannotRemoveLastOperator();

    constructor(
        address _token,
        address[] memory _initialOperators,
        uint256 _initialThreshold,
        uint256 _baseDailyCap,
        uint256 _dailyCapIncrement
    ) EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
        if (_token == address(0)) revert ZeroAddress();
        if (_initialOperators.length == 0) revert EmptyOperatorSet();
        if (_initialThreshold == 0 || _initialThreshold > _initialOperators.length) revert InvalidThreshold();

        token = IERC20(_token);
        launchTimestamp = block.timestamp;
        threshold = _initialThreshold;
        baseDailyCap = _baseDailyCap;
        dailyCapIncrement = _dailyCapIncrement;

        for (uint256 i = 0; i < _initialOperators.length; i++) {
            address op = _initialOperators[i];
            if (op == address(0)) revert ZeroAddress();
            if (isOperator[op]) revert AlreadyOperator(op);
            isOperator[op] = true;
            _operatorList.push(op);
        }
    }

    // ──────────────────── Deposit (BSC → MXD) ────────────────────

    /**
     * @notice Bridge BNBMXD tokens to MXD chain. Caller must `approve(this, amount)` on
     *         the BNBMXD token first; this call then moves the tokens directly to the
     *         burn address (`0x…dEaD`) in one atomic step. The bridge contract itself
     *         never holds BNBMXD — meaning `recoverToken` has no BNBMXD to drain even
     *         if its safeguard were bypassed.
     * @param mxdRecipient  32-byte addr32 = SHA-512(algo_id || pubkey)[0..31]. Pure hash
     *                      bytes — no version byte, no checksum. The textual mx+Base58Check
     *                      form is the wallet's UI concern; this contract sees raw 32 bytes.
     *                      The MXD-side oracle and C node validate the destination — an
     *                      addr32 with no matching pubkey holder is a self-inflicted loss,
     *                      not a system risk.
     * @param amount        BNBMXD amount in 8-decimal base units (1 MXD = 10^8).
     */
    function deposit(bytes32 mxdRecipient, uint256 amount) external {
        if (paused) revert BridgePaused();
        if (amount == 0) revert ZeroAmount();
        if (mxdRecipient == bytes32(0)) revert ZeroAddress();

        uint256 currentDay = (block.timestamp - launchTimestamp) / 1 days;
        uint256 cap = baseDailyCap + (currentDay * dailyCapIncrement);

        if (currentDay != lastDepositDay) {
            lastDepositDay = currentDay;
            dailyDepositTotal = 0;
        }

        uint256 remaining = cap - dailyDepositTotal;
        if (amount > remaining) revert DailyCapExceeded(amount, remaining);
        dailyDepositTotal += amount;

        token.safeTransferFrom(msg.sender, BURN_ADDRESS, amount);

        uint256 id = depositCount++;
        emit Deposit(msg.sender, mxdRecipient, amount, id, block.timestamp);
    }

    // ──────────────────── K-of-N admin actions ────────────────────

    function addOperator(
        address operator,
        bytes32 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        if (operator == address(0)) revert ZeroAddress();
        if (isOperator[operator]) revert AlreadyOperator(operator);

        bytes32 structHash = keccak256(abi.encode(ADD_OPERATOR_TYPEHASH, operator, nonce, deadline));
        _consumeAdminAction(structHash, nonce, deadline, signatures);

        isOperator[operator] = true;
        _operatorList.push(operator);

        emit OperatorAdded(operator, nonce);
    }

    function removeOperator(
        address operator,
        bytes32 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        if (!isOperator[operator]) revert NotOperator();
        if (_operatorList.length == 1) revert CannotRemoveLastOperator();

        bytes32 structHash = keccak256(abi.encode(REMOVE_OPERATOR_TYPEHASH, operator, nonce, deadline));
        _consumeAdminAction(structHash, nonce, deadline, signatures);

        isOperator[operator] = false;
        uint256 len = _operatorList.length;
        for (uint256 i = 0; i < len; i++) {
            if (_operatorList[i] == operator) {
                _operatorList[i] = _operatorList[len - 1];
                _operatorList.pop();
                break;
            }
        }

        // Clamp threshold if it now exceeds operator count.
        if (threshold > _operatorList.length) {
            threshold = _operatorList.length;
            emit ThresholdUpdated(threshold, nonce);
        }

        emit OperatorRemoved(operator, nonce);
    }

    function setThreshold(
        uint256 newThreshold,
        bytes32 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        if (newThreshold == 0 || newThreshold > _operatorList.length) revert InvalidThreshold();

        bytes32 structHash = keccak256(abi.encode(SET_THRESHOLD_TYPEHASH, newThreshold, nonce, deadline));
        _consumeAdminAction(structHash, nonce, deadline, signatures);

        threshold = newThreshold;
        emit ThresholdUpdated(newThreshold, nonce);
    }

    function updateDailyCap(
        uint256 newBaseCap,
        uint256 newIncrement,
        bytes32 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(UPDATE_DAILY_CAP_TYPEHASH, newBaseCap, newIncrement, nonce, deadline)
        );
        _consumeAdminAction(structHash, nonce, deadline, signatures);

        baseDailyCap = newBaseCap;
        dailyCapIncrement = newIncrement;
        emit DailyCapUpdated(newBaseCap, newIncrement, nonce);
    }

    function pause(bytes32 nonce, uint256 deadline, bytes[] calldata signatures) external {
        if (paused) revert BridgePaused();
        bytes32 structHash = keccak256(abi.encode(PAUSE_TYPEHASH, nonce, deadline));
        _consumeAdminAction(structHash, nonce, deadline, signatures);
        paused = true;
        emit Paused(nonce);
    }

    function unpause(bytes32 nonce, uint256 deadline, bytes[] calldata signatures) external {
        if (!paused) revert BridgeNotPaused();
        bytes32 structHash = keccak256(abi.encode(UNPAUSE_TYPEHASH, nonce, deadline));
        _consumeAdminAction(structHash, nonce, deadline, signatures);
        paused = false;
        emit Unpaused(nonce);
    }

    /**
     * @notice Rescue tokens accidentally sent to this contract.
     *
     *         In normal operation the bridge holds zero BNBMXD — `deposit()` moves
     *         tokens straight to `BURN_ADDRESS` and never to `address(this)`. The
     *         BNBMXD-self-recovery block below is therefore defense-in-depth, not
     *         load-bearing: it guards against the case where a depositor mistakenly
     *         calls `transfer()` on BNBMXD with the bridge address as recipient (instead
     *         of `approve` + `deposit`). Without the guard, K-of-N operator collusion
     *         could then sweep those stranded tokens. With the guard, mis-sent BNBMXD
     *         is permanently stuck at the bridge — same as if it had been sent to
     *         `0x…dEaD` directly. Acceptable failure mode; not a recoverable one.
     */
    function recoverToken(
        address tokenAddr,
        address recipient,
        uint256 amount,
        bytes32 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        if (recipient == address(0)) revert ZeroAddress();
        if (tokenAddr == address(token)) revert CannotRecoverBridgeToken();

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TOKEN_TYPEHASH, tokenAddr, recipient, amount, nonce, deadline)
        );
        _consumeAdminAction(structHash, nonce, deadline, signatures);

        IERC20(tokenAddr).transfer(recipient, amount);
        emit TokenRecovered(tokenAddr, recipient, amount, nonce);
    }

    // ──────────────────── Internal ────────────────────

    function _consumeAdminAction(
        bytes32 structHash,
        bytes32 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) internal {
        if (block.timestamp > deadline) revert DeadlineExpired(deadline);
        if (usedNonces[nonce]) revert NonceAlreadyUsed(nonce);
        if (signatures.length < threshold) revert InsufficientSignatures(signatures.length, threshold);

        bytes32 digest = _hashTypedDataV4(structHash);
        address[] memory seen = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signatures[i]);
            if (err != ECDSA.RecoverError.NoError) revert InvalidSignature();
            if (!isOperator[signer]) revert InvalidSignature();

            for (uint256 j = 0; j < i; j++) {
                if (seen[j] == signer) revert DuplicateSigner(signer);
            }
            seen[i] = signer;
        }

        usedNonces[nonce] = true;
    }

    // ──────────────────── Views ────────────────────

    function operatorCount() external view returns (uint256) {
        return _operatorList.length;
    }

    function getOperators() external view returns (address[] memory) {
        return _operatorList;
    }

    function currentDayNumber() public view returns (uint256) {
        return (block.timestamp - launchTimestamp) / 1 days;
    }

    function currentDailyCap() public view returns (uint256) {
        return baseDailyCap + (currentDayNumber() * dailyCapIncrement);
    }

    function dailyDepositUsed() public view returns (uint256) {
        if (currentDayNumber() != lastDepositDay) return 0;
        return dailyDepositTotal;
    }

    function dailyDepositRemaining() public view returns (uint256) {
        return currentDailyCap() - dailyDepositUsed();
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
