// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

/**
 * @title KipuBankV2
 * @author Hernan Fiorini
 * @notice Advanced multi-token vault with Chainlink price feeds and role-based access control
 * @dev Implements PULL pattern, multi-token accounting, and USD-normalized bank cap
 */
contract KipuBankV2 is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Represents a user's vault state for a specific token
    struct VaultBalance {
        uint256 deposited;           // Amount deposited and available
        uint256 pendingWithdrawal;   // Amount marked for withdrawal (PULL pattern)
    }

    /// @notice Transaction type for event logging
    enum TransactionType {
        DEPOSIT,
        WITHDRAWAL_REQUESTED,
        WITHDRAWAL_CLAIMED
    }

    /// @notice Role identifier for administrators
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Role identifier for operators (can pause/unpause)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Address representing native ETH in our system
    address public constant NATIVE_TOKEN = address(0);

    /// @notice USDC decimals for internal accounting normalization
    uint8 public constant ACCOUNTING_DECIMALS = 6;

    /// @notice Maximum staleness allowed for price feeds (1 hour)
    uint256 public constant PRICE_FEED_TIMEOUT = 1 hours;

    /// @notice Chainlink price feed decimals (standard)
    uint8 public constant CHAINLINK_DECIMALS = 8;

    /// @notice ETH decimals
    uint8 public constant ETH_DECIMALS = 18;

    /// @notice Maximum withdrawal limit in USD (normalized to 6 decimals)
    /// @dev Example: 10,000 USD = 10_000_000_000 (10k with 6 decimals)
    uint256 public immutable WITHDRAWAL_LIMIT_USD;

    /// @notice Maximum bank capacity in USD (normalized to 6 decimals)
    /// @dev Example: 1,000,000 USD = 1_000_000_000_000 (1M with 6 decimals)
    uint256 public immutable BANK_CAP_USD;

    /// @notice Chainlink ETH/USD price feed
    AggregatorV3Interface public immutable ETH_USD_PRICE_FEED;

    /// @notice Nested mapping: user => token => VaultBalance
    /// @dev address(0) represents ETH
    mapping(address user => mapping(address token => VaultBalance)) private s_vaults;

    /// @notice Mapping of allowed ERC20 tokens with their Chainlink price feeds
    /// @dev token address => price feed address
    mapping(address token => address priceFeed) private s_allowedTokens;

    /// @notice Mapping of token decimals for normalization
    mapping(address token => uint8 decimals) private s_tokenDecimals;

    /// @notice Total deposits counter
    uint256 private s_totalDeposits;

    /// @notice Total withdrawals counter
    uint256 private s_totalWithdrawals;

    /// @notice Emitted when a deposit occurs
    event TokenDeposited(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 amountUSD,
        uint256 newBalance
    );

    /// @notice Emitted when a withdrawal is requested
    event WithdrawalRequested(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 amountUSD,
        uint256 newBalance
    );

    /// @notice Emitted when a withdrawal is claimed
    event WithdrawalClaimed(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 amountUSD
    );

    /// @notice Emitted when a new token is added
    event TokenAdded(address indexed token, address indexed priceFeed, uint8 decimals);

    /// @notice Emitted when a token is removed
    event TokenRemoved(address indexed token);

    error KipuBankV2__AmountMustBeGreaterThanZero();
    error KipuBankV2__DepositExceedsBankCap(uint256 currentCapUSD, uint256 maxCapUSD);
    error KipuBankV2__WithdrawalExceedsLimit(uint256 amountUSD, uint256 limitUSD);
    error KipuBankV2__InsufficientBalance(uint256 requested, uint256 available);
    error KipuBankV2__NoPendingWithdrawals();
    error KipuBankV2__TransferFailed();
    error KipuBankV2__TokenNotAllowed(address token);
    error KipuBankV2__InvalidPriceFeed();
    error KipuBankV2__StalePrice();
    error KipuBankV2__InvalidPrice();

    modifier validAmount(uint256 amount) {
        if (amount == 0) revert KipuBankV2__AmountMustBeGreaterThanZero();
        _;
    }

    modifier tokenAllowed(address token) {
        if (token != NATIVE_TOKEN && s_allowedTokens[token] == address(0)) {
            revert KipuBankV2__TokenNotAllowed(token);
        }
        _;
    }

    /**
     * @notice Initializes KipuBankV2 with USD-denominated limits
     * @param withdrawalLimitUSD Maximum withdrawal in USD (6 decimals)
     * @param bankCapUSD Maximum bank capacity in USD (6 decimals)
     * @param ethUsdPriceFeed Chainlink ETH/USD price feed address
     */
    constructor(
        uint256 withdrawalLimitUSD,
        uint256 bankCapUSD,
        address ethUsdPriceFeed
    ) {
        if (ethUsdPriceFeed == address(0)) revert KipuBankV2__InvalidPriceFeed();

        WITHDRAWAL_LIMIT_USD = withdrawalLimitUSD;
        BANK_CAP_USD = bankCapUSD;
        ETH_USD_PRICE_FEED = AggregatorV3Interface(ethUsdPriceFeed);

        // Setup roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        // Configure native ETH
        s_tokenDecimals[NATIVE_TOKEN] = ETH_DECIMALS;
    }

    /**
     * @notice Deposit native ETH into vault
     * @dev Uses address(0) to represent ETH
     */
    function depositETH() 
        external 
        payable 
        whenNotPaused 
        nonReentrant 
        validAmount(msg.value) 
    {
        _deposit(NATIVE_TOKEN, msg.value);
    }

    /**
     * @notice Deposit ERC20 tokens into vault
     * @param token ERC20 token address
     * @param amount Amount of tokens to deposit
     */
    function depositToken(address token, uint256 amount)
        external
        whenNotPaused
        nonReentrant
        validAmount(amount)
        tokenAllowed(token)
    {
        // Transfer tokens from user to contract
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        _deposit(token, amount);
    }

    /**
     * @notice Request withdrawal from vault (PULL pattern - step 1)
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to withdraw
     */
    function withdraw(address token, uint256 amount)
        external
        whenNotPaused
        nonReentrant
        validAmount(amount)
        tokenAllowed(token)
    {
        VaultBalance storage vault = s_vaults[msg.sender][token];

        // Check sufficient balance
        if (vault.deposited < amount) {
            revert KipuBankV2__InsufficientBalance(amount, vault.deposited);
        }

        // Get USD value and check withdrawal limit
        uint256 amountUSD = _getValueInUSD(token, amount);
        if (amountUSD > WITHDRAWAL_LIMIT_USD) {
            revert KipuBankV2__WithdrawalExceedsLimit(amountUSD, WITHDRAWAL_LIMIT_USD);
        }

        // Effects: Update balances
        uint256 newBalance;
        uint256 newPending;
        unchecked {
            newBalance = vault.deposited - amount;
            newPending = vault.pendingWithdrawal + amount;
            s_totalWithdrawals++;
        }

        vault.deposited = newBalance;
        vault.pendingWithdrawal = newPending;

        emit WithdrawalRequested(msg.sender, token, amount, amountUSD, newBalance);
    }

    /**
     * @notice Claim pending withdrawal (PULL pattern - step 2)
     * @param token Token address to claim
     */
    function claimWithdrawal(address token)
        external
        whenNotPaused
        nonReentrant
        tokenAllowed(token)
    {
        uint256 amount = s_vaults[msg.sender][token].pendingWithdrawal;

        if (amount == 0) revert KipuBankV2__NoPendingWithdrawals();

        // Effects: Clear pending before transfer
        s_vaults[msg.sender][token].pendingWithdrawal = 0;

        // Get USD value for event
        uint256 amountUSD = _getValueInUSD(token, amount);

        // Interactions: Transfer tokens
        if (token == NATIVE_TOKEN) {
            _transferETH(msg.sender, amount);
        } else {
            IERC20(token).safeTransfer(msg.sender, amount);
        }

        emit WithdrawalClaimed(msg.sender, token, amount, amountUSD);
    }

    /**
     * @notice Add a new supported ERC20 token
     * @param token Token address
     * @param priceFeed Chainlink price feed for token/USD
     * @param decimals Token decimals
     */
    function addToken(address token, address priceFeed, uint8 decimals)
        external
        onlyRole(ADMIN_ROLE)
    {
        if (token == NATIVE_TOKEN) revert KipuBankV2__TokenNotAllowed(token);
        if (priceFeed == address(0)) revert KipuBankV2__InvalidPriceFeed();

        s_allowedTokens[token] = priceFeed;
        s_tokenDecimals[token] = decimals;

        emit TokenAdded(token, priceFeed, decimals);
    }

    /**
     * @notice Remove a supported token
     * @param token Token address to remove
     */
    function removeToken(address token) external onlyRole(ADMIN_ROLE) {
        if (token == NATIVE_TOKEN) revert KipuBankV2__TokenNotAllowed(token);
        
        delete s_allowedTokens[token];
        delete s_tokenDecimals[token];

        emit TokenRemoved(token);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Get vault balance for a user and token
     * @param user User address
     * @param token Token address
     * @return deposited Available balance
     * @return pendingWithdrawal Pending withdrawal amount
     */
    function getVaultBalance(address user, address token)
        external
        view
        returns (uint256 deposited, uint256 pendingWithdrawal)
    {
        VaultBalance memory vault = s_vaults[user][token];
        return (vault.deposited, vault.pendingWithdrawal);
    }

    /**
     * @notice Get vault balance in USD
     * @param user User address
     * @param token Token address
     * @return depositedUSD USD value of deposited amount
     * @return pendingUSD USD value of pending withdrawal
     */
    function getVaultBalanceUSD(address user, address token)
        external
        view
        returns (uint256 depositedUSD, uint256 pendingUSD)
    {
        VaultBalance memory vault = s_vaults[user][token];
        depositedUSD = _getValueInUSD(token, vault.deposited);
        pendingUSD = _getValueInUSD(token, vault.pendingWithdrawal);
    }

    /**
     * @notice Get total bank balance in USD across all tokens
     * @return totalUSD Total value in USD (6 decimals)
     */
    function getTotalBankBalanceUSD() external view returns (uint256 totalUSD) {
        // Get ETH balance
        uint256 ethBalance = address(this).balance;
        totalUSD = _getValueInUSD(NATIVE_TOKEN, ethBalance);

        // Note: For production, you'd need to track all token balances
        // This is a simplified version
        return totalUSD;
    }

    /**
     * @notice Get current ETH price in USD
     * @return price ETH price (8 decimals from Chainlink)
     */
    function getETHPrice() external view returns (uint256 price) {
        (, int256 answer,,,) = ETH_USD_PRICE_FEED.latestRoundData();
        return uint256(answer);
    }

    /**
     * @notice Check if a token is allowed
     * @param token Token address to check
     * @return True if token is allowed
     */
    function isTokenAllowed(address token) external view returns (bool) {
        return token == NATIVE_TOKEN || s_allowedTokens[token] != address(0);
    }

    /**
     * @notice Get total number of deposits
     * @return Total deposits counter
     */
    function getTotalDeposits() external view returns (uint256) {
        return s_totalDeposits;
    }

    /**
     * @notice Get total number of withdrawals
     * @return Total withdrawals counter
     */
    function getTotalWithdrawals() external view returns (uint256) {
        return s_totalWithdrawals;
    }

    /**
     * @notice Get withdrawal limit in USD
     * @return Withdrawal limit (6 decimals)
     */
    function getWithdrawalLimitUSD() external view returns (uint256) {
        return WITHDRAWAL_LIMIT_USD;
    }

    /**
     * @notice Get bank capacity in USD
     * @return Bank cap (6 decimals)
     */
    function getBankCapUSD() external view returns (uint256) {
        return BANK_CAP_USD;
    }

    /**
     * @notice Internal deposit logic with bank cap check
     * @param token Token address
     * @param amount Amount to deposit
     */
    function _deposit(address token, uint256 amount) private {
        // Check bank cap in USD
        uint256 depositValueUSD = _getValueInUSD(token, amount);
        uint256 currentTotalUSD = this.getTotalBankBalanceUSD();
        
        if (currentTotalUSD + depositValueUSD > BANK_CAP_USD) {
            revert KipuBankV2__DepositExceedsBankCap(
                currentTotalUSD + depositValueUSD,
                BANK_CAP_USD
            );
        }

        // Effects: Update vault balance
        VaultBalance storage vault = s_vaults[msg.sender][token];
        uint256 newBalance;
        unchecked {
            newBalance = vault.deposited + amount;
            s_totalDeposits++;
        }
        vault.deposited = newBalance;

        emit TokenDeposited(msg.sender, token, amount, depositValueUSD, newBalance);
    }

    /**
     * @notice Convert token amount to USD value (normalized to 6 decimals)
     * @param token Token address
     * @param amount Token amount
     * @return valueUSD USD value with 6 decimals
     */
    function _getValueInUSD(address token, uint256 amount) private view returns (uint256 valueUSD) {
        if (amount == 0) return 0;

        address priceFeed = token == NATIVE_TOKEN 
            ? address(ETH_USD_PRICE_FEED) 
            : s_allowedTokens[token];

        // Get price from Chainlink
        (, int256 price,, uint256 updatedAt,) = AggregatorV3Interface(priceFeed).latestRoundData();

        // Validate price data
        if (price <= 0) revert KipuBankV2__InvalidPrice();
        if (updatedAt < block.timestamp - PRICE_FEED_TIMEOUT) revert KipuBankV2__StalePrice();

        // Convert to USD with 6 decimals
        uint8 tokenDecimals = s_tokenDecimals[token];
        uint8 priceDecimals = AggregatorV3Interface(priceFeed).decimals();

        // Formula: (amount * price) / (10^tokenDecimals) * (10^ACCOUNTING_DECIMALS) / (10^priceDecimals)
        // Simplified: (amount * price * 10^ACCOUNTING_DECIMALS) / (10^tokenDecimals * 10^priceDecimals)
        
        valueUSD = (amount * uint256(price) * (10 ** ACCOUNTING_DECIMALS)) 
                   / (10 ** tokenDecimals * 10 ** priceDecimals);

        return valueUSD;
    }

    /**
     * @notice Safely transfer ETH
     * @param to Recipient address
     * @param amount Amount to transfer
     */
    function _transferETH(address to, uint256 amount) private {
        (bool success,) = payable(to).call{value: amount}("");
        if (!success) revert KipuBankV2__TransferFailed();
    }

    /**
     * @notice Allow contract to receive ETH
     */
    receive() external payable {
        revert KipuBankV2__AmountMustBeGreaterThanZero();
    }
}