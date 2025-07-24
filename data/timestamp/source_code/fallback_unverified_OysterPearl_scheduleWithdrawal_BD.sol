/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction withdrawal system. The vulnerability requires: 1) First transaction to schedule a withdrawal with scheduleWithdrawal() 2) Wait for time to pass 3) Second transaction to execute with executeScheduledWithdrawal(). A malicious miner can manipulate the timestamp to execute withdrawals earlier than intended by setting block.timestamp (now) to a future value, bypassing the intended delay mechanism. This creates a stateful vulnerability that persists across multiple transactions and requires accumulated state changes.
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

    uint256 public withdrawalDeadline;
    uint256 public scheduledWithdrawalAmount;
    bool public withdrawalScheduled;
    
    function PearlBonus() public {
        director = msg.sender;
        partner = 0x36B786f3EC7DE8aC4878980f4B021DE62DDDFF41;
        share = 4;
        funds = 0;
        saleClosed = false;
        withdrawalDeadline = 0;
        scheduledWithdrawalAmount = 0;
        withdrawalScheduled = false;
    }
    
    modifier onlyDirector {
        // Only the director is permitted
        require(msg.sender == director);
        _;
    }
    
    /**
     * Schedule a withdrawal that can be executed after a delay
     */
    function scheduleWithdrawal(uint256 _amount, uint256 _delay) public onlyDirector {
        require(_amount > 0);
        require(_delay >= 300); // Minimum 5 minutes delay
        require(!withdrawalScheduled);
        
        withdrawalDeadline = now + _delay;
        scheduledWithdrawalAmount = _amount;
        withdrawalScheduled = true;
    }

    /**
     * Execute a previously scheduled withdrawal
     */
    function executeScheduledWithdrawal() public onlyDirector {
        require(withdrawalScheduled);
        require(now >= withdrawalDeadline);
        require(scheduledWithdrawalAmount <= this.balance);
        
        director.transfer(scheduledWithdrawalAmount);
        
        // Reset withdrawal state
        withdrawalScheduled = false;
        withdrawalDeadline = 0;
        scheduledWithdrawalAmount = 0;
    }
    /**
     * Cancel a scheduled withdrawal
     */
    function cancelScheduledWithdrawal() public onlyDirector {
        require(withdrawalScheduled);
        
        withdrawalScheduled = false;
        withdrawalDeadline = 0;
        scheduledWithdrawalAmount = 0;
    }
    /**
     * Director can close the crowdsale
     */
    function closeSale() public onlyDirector returns (bool success) {
        // The sale must be currently open
        require(!saleClosed);
        
        // Lock the crowdsale
        saleClosed = true;
        return true;
    }

    /**
     * Director can open the crowdsale
     */
    function openSale() public onlyDirector returns (bool success) {
        // The sale must be currently closed
        require(saleClosed);
        
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
