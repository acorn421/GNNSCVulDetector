/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeDelayedTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a stateful, multi-transaction timestamp dependence issue. The exploit requires two separate transactions: first calling requestTokenClaim() to initiate a delayed claim, then calling claimTimeDelayedTokens() after the delay period. The vulnerability lies in the use of 'now' (block.timestamp) for time comparisons, which can be manipulated by miners within certain bounds. A malicious miner could manipulate the timestamp to either bypass the delay period or cause legitimate users to wait longer than intended. The state persists between transactions through the claimRequestTime and pendingClaimAmount mappings, making this a true stateful vulnerability that requires multiple calls to exploit.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public claimDelay = 3600; // 1 hour delay
    mapping(address => uint256) public claimRequestTime;
    mapping(address => uint256) public pendingClaimAmount;
    // === END FALLBACK INJECTION ===
    
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
     * Request to claim tokens with time delay for security
     * First transaction: initiate claim request
     */
    function requestTokenClaim(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        require(pendingClaimAmount[msg.sender] == 0, "Previous claim still pending");
        
        pendingClaimAmount[msg.sender] = amount;
        claimRequestTime[msg.sender] = now; // Vulnerable to timestamp manipulation
        balanceOf[msg.sender] -= amount;
    }

    /**
     * Claim tokens after time delay has passed
     * Second transaction: complete the claim
     */
    function claimTimeDelayedTokens() public {
        require(pendingClaimAmount[msg.sender] > 0, "No pending claim");
        require(now >= claimRequestTime[msg.sender] + claimDelay, "Time delay not met"); // Vulnerable to timestamp manipulation
        
        uint256 claimAmount = pendingClaimAmount[msg.sender];
        pendingClaimAmount[msg.sender] = 0;
        claimRequestTime[msg.sender] = 0;
        
        tokenReward.transfer(msg.sender, claimAmount);
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
