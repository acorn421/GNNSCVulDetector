/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawAvailableToken
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based withdrawal restrictions using block.timestamp. The vulnerability requires multiple state variables (lastWithdrawalTime, withdrawalCooldown, dailyLimitResetTime, dailyWithdrawnAmount, dailyWithdrawalLimit, totalWithdrawals) that persist between transactions. The exploit involves manipulating block timestamps across multiple transactions to bypass withdrawal cooldowns and daily limits, requiring miners to manipulate timestamps in sequential blocks to enable larger withdrawals than intended.
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

    // State variables for Timestamp Dependence block
    uint256 public lastWithdrawalTime = 0;
    uint256 public withdrawalCooldown = 1 hours; // example cooldown (can be set elsewhere)
    uint256 public totalWithdrawals = 0;
    uint256 public dailyLimitResetTime = 0;
    uint256 public dailyWithdrawnAmount = 0;
    uint256 public dailyWithdrawalLimit = 1000000 ether;
    
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based withdrawal restrictions using block.timestamp
        if (lastWithdrawalTime == 0) {
            lastWithdrawalTime = block.timestamp;
        } else {
            require(block.timestamp >= lastWithdrawalTime + withdrawalCooldown, "Withdrawal cooldown period not met");
        }
        
        // Update withdrawal tracking state
        lastWithdrawalTime = block.timestamp;
        totalWithdrawals += amount;
        
        // Time-based withdrawal limit that resets every 24 hours
        if (block.timestamp >= dailyLimitResetTime + 86400) {
            dailyWithdrawnAmount = 0;
            dailyLimitResetTime = block.timestamp;
        }
        
        // Check daily withdrawal limit based on timestamp
        require(dailyWithdrawnAmount + amount <= dailyWithdrawalLimit, "Daily withdrawal limit exceeded");
        dailyWithdrawnAmount += amount;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
