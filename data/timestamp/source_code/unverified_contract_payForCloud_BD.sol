/*
 * ===== SmartInject Injection Details =====
 * Function      : payForCloud
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through time-based pricing and accumulated usage tracking. The vulnerability allows miners to manipulate block timestamps to affect pricing across multiple transactions, while legitimate users must accumulate usage over time to get discounts.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables** (to be added to contract):
 *    - `lastPaymentTimestamp`: Tracks when each user last made a payment
 *    - `accumulatedUsage`: Tracks cumulative token usage for volume discounts
 *    - `BILLING_CYCLE`: 24-hour billing cycle constant
 * 
 * 2. **Time-Based Pricing Logic**:
 *    - Uses `block.timestamp` to determine current time
 *    - Implements peak-hour pricing (9 AM - 5 PM) with 50% premium
 *    - Calculates time since last payment for billing cycle management
 * 
 * 3. **Accumulated Usage Tracking**:
 *    - Maintains running total of tokens used per user
 *    - Provides 20% discount for users with >10,000 accumulated tokens
 *    - Resets accumulated usage after each billing cycle
 * 
 * 4. **Dynamic Price Calculation**:
 *    - Adjusts token cost based on time and usage patterns
 *    - Requires sufficient balance for adjusted amount
 * 
 * **Multi-Transaction Exploitation:**
 * 
 * The vulnerability requires multiple transactions because:
 * 
 * 1. **Volume Discount Accumulation**: Users must make multiple payments over time to accumulate >10,000 tokens for the discount. This state persists across transactions.
 * 
 * 2. **Billing Cycle State**: The accumulated usage only resets after the billing cycle, requiring time progression between transactions.
 * 
 * 3. **Timestamp Manipulation Attack**: Miners can exploit this across multiple blocks by:
 *    - Transaction 1: Make payment during off-peak hours (lower price)
 *    - Transaction 2: Manipulate timestamp to simulate billing cycle reset
 *    - Transaction 3: Continue making payments with artificially maintained low usage counts
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - **State Accumulation**: The discount mechanism depends on `accumulatedUsage` building up over multiple calls
 * - **Time Progression**: Billing cycles require real time passage between transactions
 * - **Exploitation Sequence**: Attackers need to establish usage patterns first, then exploit timestamp manipulation
 * - **Persistent State**: The vulnerability depends on state variables that persist between function calls
 * 
 * The vulnerability is realistic because cloud services commonly use time-based pricing and volume discounts, but the reliance on `block.timestamp` makes it vulnerable to miner manipulation across multiple transactions.
 */
pragma solidity >=0.4.0 <0.7.0;

contract SpaciumToken {
    
    string public constant name = "Spacium Token";
    string public constant symbol = "SPC";
    uint8 public constant decimals = 18;
    
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event HostingPayment(address indexed from, uint tokens);
    event StorePayment(address indexed from, uint tokens);
    event CloudPayment(address indexed from, uint tokens);
    
    mapping(address => uint256) balances;

    mapping(address => mapping (address => uint256)) allowed;
    
    uint256 totalSupply_;
    address public constant hostingAccountAddress = 0xdc1787eF8536235198fE5aEd66Fc3A73DEd31280;
    address public constant storeAccountAddress = 0x017A759A2095841122b4b4e90e40AE579a4361f1;
    address public constant cloudAccountAddress = 0x38C6Ec7331ce04891154b953a79B157703CaE38a;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY STATE VARIABLES START =====
    mapping(address => uint256) lastPaymentTimestamp;
    mapping(address => uint256) accumulatedUsage;
    uint256 public constant BILLING_CYCLE = 86400; // 24 hours
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY STATE VARIABLES END =====

    using SafeMath for uint256;

    
    constructor() public{
        totalSupply_ = 21000000000000000000000000;
        balances[msg.sender] = 21000000000000000000000000;
    }
    
    function totalSupply() public view returns (uint256) {
        return totalSupply_;
    }
    
    function balanceOf(address tokenOwner) public view returns (uint) {
        return balances[tokenOwner];
    }
    
    function transfer(address receiver, uint numTokens) public returns (bool) {
        require(numTokens <= balances[msg.sender]);
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[receiver] = balances[receiver].add(numTokens);
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }
    
    function approve(address delegate, uint numTokens) public returns (bool) {
        allowed[msg.sender][delegate] = numTokens;
        emit Approval(msg.sender, delegate, numTokens);
        return true;
    }
    
    function allowance(address owner, address delegate) public view returns (uint) {
        return allowed[owner][delegate];
    }
    
    function transferFrom(address owner, address buyer, uint numTokens) public returns (bool) {
        require(numTokens <= balances[owner]);    
        require(numTokens <= allowed[owner][msg.sender]);
    
        balances[owner] = balances[owner].sub(numTokens);
        allowed[owner][msg.sender] = allowed[owner][msg.sender].sub(numTokens);
        balances[buyer] = balances[buyer].add(numTokens);
        emit Transfer(owner, buyer, numTokens);
        return true;
    }
    
    function payForHosting(uint numTokens) public returns (bool){
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[hostingAccountAddress] = balances[hostingAccountAddress].add(numTokens);
        emit HostingPayment(msg.sender, numTokens);
        return true;

    }
    
    
    function payForStore(uint numTokens) public returns (bool){
        
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[storeAccountAddress] = balances[storeAccountAddress].add(numTokens);
        emit StorePayment(msg.sender, numTokens);
        return true;
    }
    
     // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // State variables injected above
    function payForCloud(uint numTokens) public returns (bool){
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based pricing with accumulated usage tracking
        uint256 currentTime = block.timestamp;
        uint256 lastPayment = lastPaymentTimestamp[msg.sender];
        
        // Calculate time-based pricing multiplier
        uint256 timeSinceLastPayment = currentTime - lastPayment;
        uint256 priceMultiplier = 100; // Base price (100%)
        
        // Peak hours (higher pricing) - vulnerable to timestamp manipulation
        uint256 hourOfDay = (currentTime / 3600) % 24;
        if (hourOfDay >= 9 && hourOfDay <= 17) {
            priceMultiplier = 150; // 50% premium during business hours
        }
        
        // Accumulated usage discount - requires multiple transactions to build up
        accumulatedUsage[msg.sender] = accumulatedUsage[msg.sender].add(numTokens);
        
        // Volume discount based on accumulated usage (stateful)
        if (accumulatedUsage[msg.sender] > 10000) {
            priceMultiplier = priceMultiplier.sub(20); // 20% discount for high usage
        }
        
        // Reset accumulated usage after billing cycle
        if (timeSinceLastPayment >= BILLING_CYCLE) {
            accumulatedUsage[msg.sender] = numTokens; // Reset to current transaction
        }
        
        // Apply time-based pricing
        uint256 adjustedTokens = (numTokens * priceMultiplier) / 100;
        require(adjustedTokens <= balances[msg.sender]);
        
        balances[msg.sender] = balances[msg.sender].sub(adjustedTokens);
        balances[cloudAccountAddress] = balances[cloudAccountAddress].add(adjustedTokens);
        
        // Update timestamp for next calculation
        lastPaymentTimestamp[msg.sender] = currentTime;
        
        emit CloudPayment(msg.sender, adjustedTokens);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return true;
    }
}

library SafeMath { 
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
      assert(b <= a);
      return a - b;
    }
    
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a + b;
      assert(c >= a);
      return c;
    }
}
