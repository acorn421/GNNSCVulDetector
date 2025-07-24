/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawAvailableToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending withdrawals mechanism that requires multiple transactions to exploit. The vulnerability is created by:
 * 
 * 1. **Added Persistent State Variables**: 
 *    - `pendingWithdrawals[address]` - tracks pending withdrawals per address across transactions
 *    - `totalPendingWithdrawals` - tracks total pending amount across all addresses
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls `withdrawAvailableToken(attackerContract, amount)` which adds to `pendingWithdrawals[attackerContract]`
 *    - **Transaction 2**: Owner calls `withdrawAvailableToken(attackerContract, amount2)` which triggers the processing of accumulated pending withdrawals
 *    - **During Transaction 2**: The `tokenReward.transfer()` call to the attacker contract can trigger reentrancy
 * 
 * 3. **Reentrancy Vulnerability**:
 *    - The external call `tokenReward.transfer(_address, withdrawAmount)` occurs before state cleanup
 *    - If `_address` is a malicious contract, it can call back into `withdrawAvailableToken` during the transfer
 *    - The reentrant call will see the old state where `pendingWithdrawals[_address]` is still non-zero
 *    - This allows the attacker to drain more tokens than intended by exploiting the accumulated pending state
 * 
 * 4. **Why Multiple Transactions Are Required**:
 *    - The vulnerability requires at least 2 transactions to build up pending withdrawals
 *    - The first transaction sets up the vulnerable state by adding to `pendingWithdrawals`
 *    - The second transaction triggers the processing that contains the reentrancy vulnerability
 *    - The attacker cannot exploit this in a single transaction because the pending state must be accumulated first
 * 
 * 5. **Realistic Implementation**:
 *    - The pending withdrawals mechanism appears to be a legitimate feature for batching withdrawals
 *    - The vulnerability is subtle and could easily be missed in code reviews
 *    - The pattern follows real-world smart contract designs that use pending/queued operations
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
    uint256 public totalPendingWithdrawals;
    
    function withdrawAvailableToken(address _address, uint amount) public onlyOwner {
        require(availableTokens >= amount);
        
        // Add to pending withdrawals that accumulate across transactions
        pendingWithdrawals[_address] += amount;
        totalPendingWithdrawals += amount;
        
        // Process pending withdrawal with external call before state updates
        if (pendingWithdrawals[_address] > 0) {
            uint256 withdrawAmount = pendingWithdrawals[_address];
            
            // External call before state cleanup - vulnerable to reentrancy
            tokenReward.transfer(_address, withdrawAmount);
            
            // State updates after external call - creates reentrancy window
            availableTokens -= withdrawAmount;
            pendingWithdrawals[_address] = 0;
            totalPendingWithdrawals -= withdrawAmount;
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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