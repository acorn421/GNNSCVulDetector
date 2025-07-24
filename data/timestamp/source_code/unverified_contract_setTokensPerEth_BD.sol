/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokensPerEth
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
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability by implementing a complex time-based price change system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added state variables for tracking price change timing (lastPriceChangeBlock, lastPriceChangeTimestamp, pendingTokensPerEth, priceChangeRequestTime)
 * 2. Implemented a dual-layer time validation system using both block.number and block.timestamp
 * 3. Added a "pending price change" mechanism that stores requested changes for later application
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Owner calls setTokensPerEth() with a high value during cooldown period, storing it as pendingTokensPerEth
 * 2. **Transaction 2**: Attacker (miner) manipulates block.timestamp to bypass the 15-minute cooldown, making the pending price change active
 * 3. **Transaction 3**: Attacker exploits the manipulated high token price through the fallback function to receive excessive tokens
 * 4. **Transaction 4**: Owner unknowingly calls setTokensPerEth() again, potentially activating the stored malicious price
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation through pendingTokensPerEth storage
 * - Miners need time to manipulate timestamps between transactions
 * - The exploit involves a sequence: setup → timestamp manipulation → price activation → exploitation
 * - Single-transaction exploitation is impossible due to the time-based validation logic and state persistence requirements
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world scenarios where developers try to implement anti-manipulation measures but create timestamp dependencies that miners can exploit across multiple blocks.
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
    
    // Added variable declarations to fix compilation errors
    uint256 public lastPriceChangeBlock;
    uint256 public lastPriceChangeTimestamp;
    uint256 public pendingTokensPerEth;
    uint256 public priceChangeRequestTime;
    
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Allow immediate price changes if more than 30 blocks have passed
        if (block.number > lastPriceChangeBlock + 30) {
            amountTokensPerEth = value;
            lastPriceChangeBlock = block.number;
        }
        // For frequent updates, use block.timestamp for "emergency" price changes
        else if (block.timestamp > lastPriceChangeTimestamp + 900) { // 15 minutes
            // Emergency price change with timestamp validation
            amountTokensPerEth = value;
            lastPriceChangeTimestamp = block.timestamp;
            lastPriceChangeBlock = block.number;
        }
        else {
            // Store pending price change to be applied later
            pendingTokensPerEth = value;
            priceChangeRequestTime = block.timestamp;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
   /**
     * Set a token contract address and available tokens and the available tokens
     * 
     */
    function setTokenReward(address _address, uint amount) public onlyOwner {
        
        tokenReward = token(_address);
        availableTokens = amount;
    }
    
   /**
     * Set available tokens to synchronized values or force to stop contribution campaign
     * 
     */
    function setAvailableToken(uint value) public onlyOwner {
        
        availableTokens = value;
    }
    
    
    
}
