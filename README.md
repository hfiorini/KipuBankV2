# KipuBankV2

**KipuBankV2** is an advanced multi-token vault system that implements role-based access control, Chainlink oracle integration, and USD-normalized accounting.

## Project Objectives

Evolution of the original KipuBank contract with the following improvements:

### Implemented Features

1. **Access Control (OpenZeppelin AccessControl)**
   - Roles: `DEFAULT_ADMIN_ROLE`, `ADMIN_ROLE`, `OPERATOR_ROLE`
   - Granular permission management
   - Protected administrative functions

2. **Multi-token Support**
   - Native ETH deposits and withdrawals (using `address(0)`)
   - ERC-20 token support
   - Token whitelist with price feeds

3. **Multi-token Internal Accounting**
   - Nested mappings: `user => token => VaultBalance`
   - Normalization to 6 decimals (USDC standard)
   - Separate tracking of balances and pending withdrawals

4. **Chainlink Oracle Integration**
   - ETH/USD and token/USD price feeds
   - Bank cap and withdrawal limits in USD
   - Stale price validation (less than 1 hour)

5. **Decimal Conversion**
   - `_getValueInUSD()` function for normalization
   - Handles different decimals per token (ETH: 18, USDC: 6, etc.)
   - Precise arithmetic considering price feed decimals (8)

6. **Type Declarations**
   - `struct VaultBalance`: Vault state per user/token
   - `enum TransactionType`: Transaction types

7. **Security and Efficiency**
   - PULL pattern for withdrawals (reentrancy protection)
   - OpenZeppelin `ReentrancyGuard` and `Pausable`
   - `SafeERC20` for secure transfers
   - `immutable` and `constant` variables
   - `unchecked` blocks where safe
   - Checks-Effects-Interactions pattern

## Project Structure

```
KipuBankV2/
├── src/
│   └── KipuBankV2.sol          # Main contract
├── test/
│   └── KipuBankV2.t.sol        # Unit tests
└── README.md
```

## Installation and Setup

### Prerequisites

- Remix IDE or local development environment
- MetaMask wallet
- Testnet ETH (Sepolia recommended)

## Testing

The contract includes comprehensive NatSpec documentation and follows Solidity best practices. Test the contract functions through Remix IDE or your preferred testing framework.

## Deployment

### Step 1: Configure Environment

Ensure you have:
- A wallet with testnet ETH
- Access to Remix IDE or similar deployment tool
- Knowledge of the network's Chainlink price feed addresses

### Step 2: Deploy on Sepolia Testnet

**Constructor Parameters:**

```
withdrawalLimitUSD: 10000000000      // $10,000 USD with 6 decimals
bankCapUSD: 1000000000000             // $1,000,000 USD with 6 decimals
ethUsdPriceFeed: 0x694AA1769357215DE4FAC081bf1f309aDC325306  // Sepolia ETH/USD
```

**Network-Specific Price Feeds:**

**Sepolia Testnet:**
```
ETH/USD: 0x694AA1769357215DE4FAC081bf1f309aDC325306
USDC/USD: 0xA2F78ab2355fe2f984D808B5CeE7FD0A93D5270E
```

**Ethereum Mainnet (for reference):**
```
ETH/USD: 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419
USDC/USD: 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6
```

### Step 3: Verify on Etherscan

After deployment, verify your contract on Etherscan:

1. Go to the contract address on Sepolia Etherscan
2. Click "Contract" > "Verify and Publish"
3. Select compiler version ^0.8.20
4. Choose "Solidity (Single file)" or provide all imports
5. Paste the contract code
6. Add constructor arguments (ABI-encoded)

## Contract Interaction

### Deposit ETH

Call the `depositETH()` function with the amount of ETH you want to deposit as the transaction value.

### Add ERC-20 Token (Admin Only)

```solidity
addToken(
    tokenAddress,      // ERC-20 token address
    priceFeedAddress,  // Chainlink price feed address
    decimals           // Token decimals (e.g., 6 for USDC)
)
```

### Deposit ERC-20 Token

1. First, approve the contract to spend your tokens
2. Call `depositToken(tokenAddress, amount)`

### Request Withdrawal

```solidity
withdraw(
    tokenAddress,  // address(0) for ETH
    amount         // Amount to withdraw
)
```

### Claim Pending Withdrawal

```solidity
claimWithdrawal(tokenAddress)  // address(0) for ETH
```

### Query Functions

- `getVaultBalance(user, token)` - Get deposited and pending amounts
- `getVaultBalanceUSD(user, token)` - Get balances in USD
- `getTotalBankBalanceUSD()` - Get total bank value in USD
- `getETHPrice()` - Get current ETH price from Chainlink
- `isTokenAllowed(token)` - Check if a token is whitelisted

## Design Decisions and Trade-offs

### 1. PULL Pattern for Withdrawals

**Decision:** Implemented a two-step withdrawal process (request + claim)

**Rationale:**
- Prevents reentrancy attacks
- Protects against denial-of-service attacks
- Users have full control over when they receive funds

**Trade-off:** Requires two transactions instead of one, increasing gas costs for users

### 2. USD-Denominated Limits

**Decision:** Bank cap and withdrawal limits are in USD (normalized to 6 decimals)

**Rationale:**
- Consistent limits across all supported tokens
- Protection against token price volatility
- Easier for users to understand limits in familiar currency

**Trade-off:** Depends on Chainlink oracles; requires price feed validation

### 3. Multi-Token Support via Nested Mappings

**Decision:** Used `mapping(address => mapping(address => VaultBalance))`

**Rationale:**
- Scalable to unlimited tokens per user
- Gas-efficient for sparse data
- Clear separation of balances per token

**Trade-off:** Cannot easily enumerate all user tokens; requires external tracking for UI

### 4. Immutable Oracle Instance

**Decision:** Price feed set at deployment, cannot be changed

**Rationale:**
- Gas savings (immutable vs storage)
- Security - prevents malicious oracle replacement
- Simplicity

**Trade-off:** Cannot upgrade to new oracle without deploying new contract

### 5. Role-Based Access Control

**Decision:** Three-tier role system (DEFAULT_ADMIN, ADMIN, OPERATOR)

**Rationale:**
- Granular permission management
- Separation of concerns (admin vs operator duties)
- Battle-tested OpenZeppelin implementation

**Trade-off:** Additional complexity in permission management

### 6. Pausable Functionality

**Decision:** Contract can be paused by operators

**Rationale:**
- Emergency stop mechanism
- Protection during security incidents
- Time to resolve issues without fund loss

**Trade-off:** Centralization risk; operators have significant power

### 7. Price Feed Timeout (1 hour)

**Decision:** Rejects price data older than 1 hour

**Rationale:**
- Balance between freshness and reliability
- Chainlink typically updates more frequently
- Protects against stale price exploitation

**Trade-off:** May fail during oracle downtime; 1 hour may be too long for volatile assets

## Security Considerations

- All external calls follow Checks-Effects-Interactions pattern
- ReentrancyGuard on all state-changing functions
- SafeERC20 for all token transfers
- Price feed validation (positive price, recent update)
- Custom errors for gas efficiency and clarity
- Comprehensive access control on admin functions

## Known Limitations

1. **Total Bank Balance Calculation:** Current implementation only accounts for ETH balance. Production version would need to track all token balances.

2. **No Token Enumeration:** Users must track their own deposited tokens; contract doesn't provide a list.

3. **Fixed Price Feed:** Cannot upgrade oracle without new deployment.

4. **Single Chain:** Designed for single EVM chain; no cross-chain support.

## Resources

- [Chainlink Price Feeds - Sepolia](https://docs.chain.link/data-feeds/price-feeds/addresses?network=ethereum&page=1#sepolia-testnet)
- [Chainlink Price Feeds - Mainnet](https://docs.chain.link/data-feeds/price-feeds/addresses?network=ethereum&page=1)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
- [Solidity Documentation](https://docs.soliditylang.org/)

## License

This project is licensed under the MIT License.

## Author

Hernan Fiorini

## Acknowledgments

This project was developed as part of an advanced Solidity course, demonstrating:
- Secure smart contract patterns
- Oracle integration
- Multi-token accounting
- Role-based access control
- Production-ready code structure and documentation