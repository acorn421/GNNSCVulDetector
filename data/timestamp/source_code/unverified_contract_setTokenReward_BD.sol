/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by:
 * 
 * 1. **Added timestamp-based state tracking**: The function now stores `lastRewardUpdateTime` which persists between transactions and creates stateful dependencies.
 * 
 * 2. **Implemented time-based calculations**: When called subsequent times, the function calculates a time-based multiplier using `block.timestamp` and the stored timestamp from previous calls.
 * 
 * 3. **Created exploitable timing logic**: The vulnerability uses `timeElapsed % 100` to determine a multiplier, making the token amount calculation dependent on block timestamps that can be manipulated by miners.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner calls setTokenReward for the first time, setting initial token reward and storing timestamp
 * - **Transaction 2+**: Subsequent calls use the time difference to calculate multipliers, allowing miners to manipulate block timestamps to influence token amounts
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability only manifests when `address(tokenReward) != address(0)` (after first call)
 * - The time-based calculation depends on the difference between current and stored timestamps
 * - Single transaction cannot exploit this as it requires accumulated state from previous calls
 * - Miners need multiple blocks to effectively manipulate timestamps for maximum benefit
 * 
 * **State Variables Required** (to be added to contract):
 * ```solidity
 * uint256 public lastRewardUpdateTime;
 * ```
 * 
 * This creates a realistic timestamp dependence vulnerability where the token reward amount can be influenced by miners manipulating block timestamps across multiple transactions.
 */
pragma solidity ^0.4.24;

interface token {
    function transfer(address receiver, uint amount) external;
}


contract Ownable {

    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
}

contract AirdropNEOC is Ownable {
    
    address public beneficiary;
    uint256 public amountTokensPerEth = 10000000;
    uint256 public amountEthRaised = 0;
    uint256 public availableTokens;
    token public tokenReward;
    mapping(address => uint256) public balanceOf;
    uint256 public lastRewardUpdateTime; // <-- Declaration added
    
    
    /**
     * Constructor function
     *
     * Set beneficiary and set the token smart contract address
     */
    constructor() public {
        
        beneficiary = msg.sender;
        tokenReward = token(0x91A6f588E5B99077da9c78667ab691564A8fA4DD);
    }

    /**
     * Fallback function
     *
     * The function without name is the default function that is called whenever anyone sends funds to a contract
     */
    function () payable public {
        
        uint256 amount = msg.value;
        uint256 tokens = amount * amountTokensPerEth;
        require(availableTokens >= amount);
        
        balanceOf[msg.sender] += amount;
        availableTokens -= tokens;
        amountEthRaised += amount;
        tokenReward.transfer(msg.sender, tokens);
        beneficiary.transfer(amount);
    }

    /**
     * Withdraw an "amount" of available tokens in the contract
     * 
     */
    function withdrawAvailableToken(address _address, uint amount) public onlyOwner {
        require(availableTokens >= amount);
        availableTokens -= amount;
        tokenReward.transfer(_address, amount);
    }
    
    /**
     * Set the amount of tokens per one ether
     * 
     */
    function setTokensPerEth(uint value) public onlyOwner {
        
        amountTokensPerEth = value;
    }
    
   /**
     * Set a token contract address and available tokens and the available tokens
     * 
     */
    function setTokenReward(address _address, uint amount) public onlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Use block.timestamp for reward calculations and timing validation
        uint256 currentTime = block.timestamp;
        
        // If this is a subsequent call, apply time-based multiplier
        if (address(tokenReward) != address(0)) {
            // Calculate time-based bonus using block.timestamp
            uint256 timeElapsed = currentTime - lastRewardUpdateTime;
            
            // Vulnerable: time-based calculations can be manipulated by miners
            if (timeElapsed > 0) {
                // Apply time-based multiplier (can be exploited with timestamp manipulation)
                uint256 timeMultiplier = (timeElapsed % 100) + 1; // 1-100 multiplier
                amount = amount * timeMultiplier / 10; // Scale the multiplier
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        tokenReward = token(_address);
        availableTokens = amount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for future calculations - creates stateful dependency
        lastRewardUpdateTime = currentTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
   /**
     * Set available tokens to synchronized values or force to stop contribution campaign
     * 
     */
    function setAvailableToken(uint value) public onlyOwner {
        
        availableTokens = value;
    }
    
    
    
}
