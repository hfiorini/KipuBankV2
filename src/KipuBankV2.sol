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
 * 
 * This contract provides a secure multi-token vault system with the following features:
 * - Support for native ETH and ERC20 tokens
 * - USD-denominated limits using Chainlink price feeds
 * - Two-step withdrawal process (PULL pattern) for enhanced security
 * - Role-based access control for administrative functions
 * - Pausable functionality for emergency stops
 * - Bank capacity limits to prevent over-deposits
 * 
 * Security features:
 * - ReentrancyGuard on all external state-changing functions
 * - Custom modifiers for validation logic
 * - Safe math operations (Solidity 0.8.20+ includes overflow checks by default)
 * - Checks-Effects-Interactions pattern
 */
contract KipuBankV2 is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Represents a user's vault state for a specific token
     * @dev Uses two separate balances to implement the PULL withdrawal pattern
     * @param deposited Amount currently deposited and available for withdrawal requests
     * @param pendingWithdrawal Amount marked for withdrawal that can be claimed
     */
    struct VaultBalance {
        uint256 deposited;           // Amount deposited and available
        uint256 pendingWithdrawal;   // Amount marked for withdrawal (PULL pattern)
    }

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Transaction type for event logging and tracking
     * @dev Used to categorize different operations in the system
     */
    enum TransactionType {
        DEPOSIT,
        WITHDRAWAL_REQUESTED,
        WITHDRAWAL_CLAIMED
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role identifier for administrators who can add/remove tokens
    /// @dev Keccak256 hash of "ADMIN_ROLE"
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Role identifier for operators who can pause/unpause the contract
    /// @dev Keccak256 hash of "OPERATOR_ROLE"
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Address representing native ETH in our system
    /// @dev We use address(0) as a sentinel value for ETH
    address public constant NATIVE_TOKEN = address(0);

    /// @notice USDC decimals for internal accounting normalization
    /// @dev All USD values are normalized to 6 decimals for consistency
    uint8 public constant ACCOUNTING_DECIMALS = 6;

    /// @notice Maximum staleness allowed for price feeds (1 hour)
    /// @dev Price data older than this will be rejected to prevent stale price attacks
    uint256 public constant PRICE_FEED_TIMEOUT = 1 hours;

    /// @notice Chainlink price feed decimals (standard)
    /// @dev Most Chainlink feeds use 8 decimals for price data
    uint8 public constant CHAINLINK_DECIMALS = 8;

    /// @notice ETH decimals
    /// @dev Native Ethereum uses 18 decimals
    uint8 public constant ETH_DECIMALS = 18;

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Maximum withdrawal limit in USD (normalized to 6 decimals)
     * @dev Example: 10,000 USD = 10_000_000_000 (10k with 6 decimals)
     * Set at construction and cannot be changed
     */
    uint256 public immutable WITHDRAWAL_LIMIT_USD;

    /**
     * @notice Maximum bank capacity in USD (normalized to 6 decimals)
     * @dev Example: 1,000,000 USD = 1_000_000_000_000 (1M with 6 decimals)
     * Set at construction and cannot be changed
     */
    uint256 public immutable BANK_CAP_USD;

    /**
     * @notice Chainlink ETH/USD price feed
     * @dev Used to convert ETH amounts to USD for limit checks
     */
    AggregatorV3Interface public immutable ETH_USD_PRICE_FEED;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Nested mapping storing vault balances
     * @dev Maps user address => token address => VaultBalance struct
     * address(0) represents ETH in this mapping
     */
    mapping(address user => mapping(address token => VaultBalance)) private s_vaults;

    /**
     * @notice Mapping of allowed ERC20 tokens with their Chainlink price feeds
     * @dev Maps token address => Chainlink price feed address
     * Only tokens in this mapping (plus ETH) can be deposited
     */
    mapping(address token => address priceFeed) private s_allowedTokens;

    /**
     * @notice Mapping of token decimals for normalization
     * @dev Maps token address => decimal count
     * Used to correctly convert token amounts to USD values
     */
    mapping(address token => uint8 decimals) private s_tokenDecimals;

    /**
     * @notice Total number of deposits made to the contract
     * @dev Incremented on each successful deposit, used for analytics
     */
    uint256 private s_totalDeposits;

    /**
     * @notice Total number of withdrawal requests made
     * @dev Incremented on each withdrawal request, used for analytics
     */
    uint256 private s_totalWithdrawals;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a user deposits tokens
     * @param user Address of the depositing user
     * @param token Address of the deposited token (address(0) for ETH)
     * @param amount Amount of tokens deposited (in token decimals)
     * @param amountUSD USD value of the deposit (6 decimals)
     * @param newBalance New total deposited balance for this user and token
     */
    event TokenDeposited(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 amountUSD,
        uint256 newBalance
    );

    /**
     * @notice Emitted when a user requests a withdrawal
     * @param user Address of the withdrawing user
     * @param token Address of the token to withdraw (address(0) for ETH)
     * @param amount Amount requested for withdrawal (in token decimals)
     * @param amountUSD USD value of the withdrawal (6 decimals)
     * @param newBalance New deposited balance after the request
     */
    event WithdrawalRequested(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 amountUSD,
        uint256 newBalance
    );

    /**
     * @notice Emitted when a user claims their pending withdrawal
     * @param user Address of the user claiming the withdrawal
     * @param token Address of the claimed token (address(0) for ETH)
     * @param amount Amount claimed (in token decimals)
     * @param amountUSD USD value of the claim (6 decimals)
     */
    event WithdrawalClaimed(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 amountUSD
    );

    /**
     * @notice Emitted when a new token is added to the allowed list
     * @param token Address of the added token
     * @param priceFeed Address of the Chainlink price feed for this token
     * @param decimals Number of decimals the token uses
     */
    event TokenAdded(address indexed token, address indexed priceFeed, uint8 decimals);

    /**
     * @notice Emitted when a token is removed from the allowed list
     * @param token Address of the removed token
     */
    event TokenRemoved(address indexed token);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a zero amount is provided where a positive amount is required
    error KipuBankV2__AmountMustBeGreaterThanZero();
    
    /**
     * @notice Thrown when a deposit would exceed the bank's capacity
     * @param currentCapUSD Current total USD value after the deposit
     * @param maxCapUSD Maximum allowed USD capacity
     */
    error KipuBankV2__DepositExceedsBankCap(uint256 currentCapUSD, uint256 maxCapUSD);
    
    /**
     * @notice Thrown when a withdrawal request exceeds the per-transaction limit
     * @param amountUSD USD value of the requested withdrawal
     * @param limitUSD Maximum allowed withdrawal in USD
     */
    error KipuBankV2__WithdrawalExceedsLimit(uint256 amountUSD, uint256 limitUSD);
    
    /**
     * @notice Thrown when trying to withdraw more than available balance
     * @param requested Amount requested for withdrawal
     * @param available Amount actually available in the vault
     */
    error KipuBankV2__InsufficientBalance(uint256 requested, uint256 available);
    
    /// @notice Thrown when trying to claim a withdrawal with no pending amount
    error KipuBankV2__NoPendingWithdrawals();
    
    /// @notice Thrown when an ETH transfer fails
    error KipuBankV2__TransferFailed();
    
    /**
     * @notice Thrown when trying to interact with a non-allowed token
     * @param token Address of the disallowed token
     */
    error KipuBankV2__TokenNotAllowed(address token);
    
    /// @notice Thrown when an invalid price feed address is provided
    error KipuBankV2__InvalidPriceFeed();
    
    /// @notice Thrown when price data is too old
    error KipuBankV2__StalePrice();
    
    /// @notice Thrown when price data is invalid (e.g., negative or zero)
    error KipuBankV2__InvalidPrice();

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that the provided amount is greater than zero
     * @param amount The amount to validate
     * @dev Reverts with KipuBankV2__AmountMustBeGreaterThanZero if amount is 0
     */
    modifier validAmount(uint256 amount) {
        if (amount == 0) revert KipuBankV2__AmountMustBeGreaterThanZero();
        _;
    }

    /**
     * @notice Validates that a token is allowed for deposits/withdrawals
     * @param token The token address to check
     * @dev Reverts with KipuBankV2__TokenNotAllowed if token is not in the allowed list
     * ETH (address(0)) is always allowed
     */
    modifier tokenAllowed(address token) {
        if (token != NATIVE_TOKEN && s_allowedTokens[token] == address(0)) {
            revert KipuBankV2__TokenNotAllowed(token);
        }
        _;
    }

    /**
     * @notice Validates that a withdrawal amount is within the USD limit
     * @param token The token being withdrawn
     * @param amount The amount being withdrawn
     * @dev Reverts with KipuBankV2__WithdrawalExceedsLimit if USD value exceeds limit
     */
    modifier withinWithdrawalLimit(address token, uint256 amount) {
        uint256 amountUSD = _getValueInUSD(token, amount);
        if (amountUSD > WITHDRAWAL_LIMIT_USD) {
            revert KipuBankV2__WithdrawalExceedsLimit(amountUSD, WITHDRAWAL_LIMIT_USD);
        }
        _;
    }

    /**
     * @notice Validates that a user has sufficient deposited balance
     * @param token The token to check balance for
     * @param amount The amount required
     * @dev Reverts with KipuBankV2__InsufficientBalance if balance is insufficient
     */
    modifier hasSufficientBalance(address token, uint256 amount) {
        uint256 available = s_vaults[msg.sender][token].deposited;
        if (available < amount) {
            revert KipuBankV2__InsufficientBalance(amount, available);
        }
        _;
    }

    /**
     * @notice Validates that a user has a pending withdrawal to claim
     * @param token The token to check for pending withdrawals
     * @dev Reverts with KipuBankV2__NoPendingWithdrawals if no pending amount exists
     */
    modifier hasPendingWithdrawal(address token) {
        if (s_vaults[msg.sender][token].pendingWithdrawal == 0) {
            revert KipuBankV2__NoPendingWithdrawals();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes KipuBankV2 with USD-denominated limits
     * @param withdrawalLimitUSD Maximum withdrawal in USD (6 decimals)
     * @param bankCapUSD Maximum bank capacity in USD (6 decimals)
     * @param ethUsdPriceFeed Chainlink ETH/USD price feed address
     * @dev Sets up roles and configures native ETH support
     * Grants DEFAULT_ADMIN_ROLE, ADMIN_ROLE, and OPERATOR_ROLE to deployer
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

    /*//////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit native ETH into vault
     * @dev Uses address(0) to represent ETH internally
     * Validates amount, checks pause status, and applies reentrancy guard
     * Emits TokenDeposited event on success
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
     * @dev Requires prior approval of tokens to this contract
     * Validates token is allowed, amount is positive, and applies security checks
     * Emits TokenDeposited event on success
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
     * @dev Moves funds from deposited to pendingWithdrawal
     * Validates amount, balance, withdrawal limit, and token allowance
     * User must call claimWithdrawal() to receive the funds
     * Emits WithdrawalRequested event on success
     */
    function withdraw(address token, uint256 amount)
        external
        whenNotPaused
        nonReentrant
        validAmount(amount)
        tokenAllowed(token)
        hasSufficientBalance(token, amount)
        withinWithdrawalLimit(token, amount)
    {
        VaultBalance storage vault = s_vaults[msg.sender][token];

        // Get USD value for event
        uint256 amountUSD = _getValueInUSD(token, amount);

        // Effects: Update balances
        // Safe to use unchecked for balance subtraction due to hasSufficientBalance modifier
        uint256 newBalance;
        uint256 newPending;
        unchecked {
            newBalance = vault.deposited - amount;
            newPending = vault.pendingWithdrawal + amount; // Can overflow, but highly unlikely in practice
        }
        
        // Counter can overflow if there are 2^256 withdrawals
        // In practice this is impossible, so we check this separately
        s_totalWithdrawals = s_totalWithdrawals + 1;

        vault.deposited = newBalance;
        vault.pendingWithdrawal = newPending;

        emit WithdrawalRequested(msg.sender, token, amount, amountUSD, newBalance);
    }

    /**
     * @notice Claim pending withdrawal (PULL pattern - step 2)
     * @param token Token address to claim
     * @dev Transfers the pending withdrawal amount to the user
     * Validates token is allowed and there is a pending withdrawal
     * Follows Checks-Effects-Interactions pattern for security
     * Emits WithdrawalClaimed event on success
     */
    function claimWithdrawal(address token)
        external
        whenNotPaused
        nonReentrant
        tokenAllowed(token)
        hasPendingWithdrawal(token)
    {
        uint256 amount = s_vaults[msg.sender][token].pendingWithdrawal;

        // Effects: Clear pending before transfer (CEI pattern)
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
     * @dev Only callable by ADMIN_ROLE
     * Cannot add native token (address(0)) as it's handled separately
     * Price feed must be a valid address
     * Emits TokenAdded event on success
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
     * @dev Only callable by ADMIN_ROLE
     * Cannot remove native token (address(0))
     * Emits TokenRemoved event on success
     */
    function removeToken(address token) external onlyRole(ADMIN_ROLE) {
        if (token == NATIVE_TOKEN) revert KipuBankV2__TokenNotAllowed(token);
        
        delete s_allowedTokens[token];
        delete s_tokenDecimals[token];

        emit TokenRemoved(token);
    }

    /**
     * @notice Pause the contract
     * @dev Only callable by OPERATOR_ROLE
     * Prevents all deposits, withdrawals, and claims while paused
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     * @dev Only callable by OPERATOR_ROLE
     * Resumes normal operations
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get vault balance for a user and token
     * @param user User address
     * @param token Token address
     * @return deposited Available balance that can be withdrawn
     * @return pendingWithdrawal Pending withdrawal amount that can be claimed
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
     * @return depositedUSD USD value of deposited amount (6 decimals)
     * @return pendingUSD USD value of pending withdrawal (6 decimals)
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
     * @dev Currently only accounts for ETH balance
     * In production, this would need to track all token balances
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
     * @return price ETH price with 8 decimals (standard Chainlink format)
     */
    function getETHPrice() external view returns (uint256 price) {
        (, int256 answer,,,) = ETH_USD_PRICE_FEED.latestRoundData();
        return uint256(answer);
    }

    /**
     * @notice Check if a token is allowed
     * @param token Token address to check
     * @return True if token is allowed for deposits/withdrawals
     */
    function isTokenAllowed(address token) external view returns (bool) {
        return token == NATIVE_TOKEN || s_allowedTokens[token] != address(0);
    }

    /**
     * @notice Get total number of deposits
     * @return Total deposits counter across all users and tokens
     */
    function getTotalDeposits() external view returns (uint256) {
        return s_totalDeposits;
    }

    /**
     * @notice Get total number of withdrawal requests
     * @return Total withdrawals counter across all users and tokens
     */
    function getTotalWithdrawals() external view returns (uint256) {
        return s_totalWithdrawals;
    }

    /**
     * @notice Get withdrawal limit in USD
     * @return Withdrawal limit with 6 decimals
     */
    function getWithdrawalLimitUSD() external view returns (uint256) {
        return WITHDRAWAL_LIMIT_USD;
    }

    /**
     * @notice Get bank capacity in USD
     * @return Bank cap with 6 decimals
     */
    function getBankCapUSD() external view returns (uint256) {
        return BANK_CAP_USD;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Internal deposit logic with bank cap check
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to deposit in token decimals
     * @dev Checks bank capacity limit before accepting deposit
     * Updates vault balance and increments deposit counter
     * Emits TokenDeposited event
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
        
        // Safe to use unchecked for addition as overflow is checked by default in 0.8.20
        // but we want to be explicit about the counter overflow
        uint256 newBalance = vault.deposited + amount;
        
        // Counter can overflow if there are 2^256 deposits
        // In practice this is impossible, so we check this separately
        s_totalDeposits = s_totalDeposits + 1;
        
        vault.deposited = newBalance;

        emit TokenDeposited(msg.sender, token, amount, depositValueUSD, newBalance);
    }

    /**
     * @notice Convert token amount to USD value (normalized to 6 decimals)
     * @param token Token address (address(0) for ETH)
     * @param amount Token amount in native token decimals
     * @return valueUSD USD value with 6 decimals
     * @dev Uses Chainlink price feeds to get current token price
     * Validates price is not stale (older than PRICE_FEED_TIMEOUT)
     * Validates price is positive
     * Normalizes result to 6 decimals regardless of token or price feed decimals
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
     * @notice Safely transfer ETH using low-level call
     * @param to Recipient address
     * @param amount Amount of ETH to transfer in wei
     * @dev Uses call instead of transfer to avoid gas limitations
     * Reverts with KipuBankV2__TransferFailed if transfer fails
     */
    function _transferETH(address to, uint256 amount) private {
        (bool success,) = payable(to).call{value: amount}("");
        if (!success) revert KipuBankV2__TransferFailed();
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE FUNCTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Reject direct ETH transfers to the contract
     * @dev Users must use depositETH() function instead
     * This prevents accidental ETH transfers that wouldn't be credited to user accounts
     */
    receive() external payable {
        revert KipuBankV2__AmountMustBeGreaterThanZero();
    }
}
