/*
 * ===== SmartInject Injection Details =====
 * Function      : openSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-based cooldown mechanism that creates a multi-transaction vulnerability. The function now relies on block.timestamp to enforce a waiting period between sale closures and reopenings. This requires state variables lastCloseTime, lastOpenTime, and cooldownPeriod to be added to the contract. The vulnerability can be exploited through:
 * 
 * 1. **Multi-Transaction Sequence**: 
 *    - Transaction 1: Director calls closeSale() which sets lastCloseTime = block.timestamp
 *    - Transaction 2: Attacker/Director attempts to call openSale() before cooldown expires
 *    - Transaction 3+: Mining manipulation or strategic timing to bypass the cooldown check
 * 
 * 2. **Timestamp Manipulation Exploitation**:
 *    - Miners can manipulate block.timestamp values (up to ~900 seconds variance allowed by Ethereum)
 *    - State persists between transactions via lastCloseTime storage
 *    - Attackers can time their transactions around timestamp manipulation opportunities
 *    - The cooldown check can be bypassed by mining blocks with manipulated timestamps
 * 
 * 3. **State Dependency**: The vulnerability requires the persistent state from previous closeSale() calls (stored in lastCloseTime) to be exploitable, making it inherently multi-transaction and stateful.
 * 
 * The vulnerability is realistic as time-based cooldowns are common in crowdsale contracts for regulatory compliance, but the reliance on block.timestamp makes it exploitable through mining manipulation across multiple transactions.
 */
pragma solidity ^0.4.18;

interface OysterPearl {
    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public;
}

contract PearlBonus {
    address public pearlContract = 0x1844b21593262668B7248d0f57a220CaaBA46ab9;
    OysterPearl pearl = OysterPearl(pearlContract);
    
    address public director;
    address public partner;
    uint8 public share;
    uint256 public funds;
    bool public saleClosed;
    
    // Add missing state variables for timestamp-related logic
    uint256 public lastCloseTime;
    uint256 public lastOpenTime;
    uint256 public cooldownPeriod = 1 days; // Set a default cooldown period
    
    constructor() public {
        director = msg.sender;
        partner = 0x36B786f3EC7DE8aC4878980f4B021DE62DDDFF41;
        share = 4;
        funds = 0;
        saleClosed = false;
        lastCloseTime = 0;
        lastOpenTime = 0;
    }
    
    modifier onlyDirector {
        // Only the director is permitted
        require(msg.sender == director);
        _;
    }
    
    /**
     * Director can close the crowdsale
     */
    function closeSale() public onlyDirector returns (bool success) {
        // The sale must be currently open
        require(!saleClosed);
        
        // Lock the crowdsale
        saleClosed = true;
        lastCloseTime = block.timestamp;
        return true;
    }

    /**
     * Director can open the crowdsale
     */
    function openSale() public onlyDirector returns (bool success) {
        // The sale must be currently closed
        require(saleClosed);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Check if enough time has passed since last closure
        // This prevents rapid open/close cycles for regulatory compliance
        if (lastCloseTime > 0) {
            require(block.timestamp >= lastCloseTime + cooldownPeriod);
        }
        
        // Store the opening time for future reference
        lastOpenTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        // Unlock the crowdsale
        saleClosed = false;
        return true;
    }
    
    function transfer(address _send, uint256 _amount) public onlyDirector {
        pearl.transfer(_send, _amount);
    }
    
    /**
     * Transfers the director to a new address
     */
    function transferDirector(address newDirector) public onlyDirector {
        director = newDirector;
    }
    
    /**
     * Withdraw funds from the contract (failsafe)
     */
    function withdrawFunds() public onlyDirector {
        director.transfer(this.balance);
    }

     /**
     * Crowdsale function
     */
    function () public payable {
        // Check if crowdsale is still active
        require(!saleClosed);
        
        // Minimum amount is 1 finney
        require(msg.value >= 1 finney);
        
        // Price is 1 ETH = 6000 PRL
        uint256 amount = msg.value * 6000;
        
        require(amount <= pearl.balanceOf(this));
        
        pearl.transfer(msg.sender, amount);
        
        // Track ETH amount raised
        funds += msg.value;
        
        // Auto withdraw
        uint256 partnerShare = (this.balance / 100) * share;
        director.transfer(this.balance - partnerShare);
        partner.transfer(partnerShare);
    }
}
