/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a 3-phase withdrawal system that requires multiple transactions to complete. The vulnerability occurs in phase 3 where the external call to director.transfer() happens before state variables are reset, allowing for reentrancy attacks after the vulnerable state has been accumulated through the previous transactions. The attack requires: 1) Transaction 1 to initiate (phase 1), 2) Transaction 2 to confirm after delay (phase 2), and 3) Transaction 3 to execute where reentrancy can occur. This creates a realistic scenario where the attacker must build up the withdrawal state across multiple transactions before the reentrancy vulnerability becomes exploitable.
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
    
    // Added missing state variables needed for withdrawFunds
    uint8 public withdrawalPhase;
    uint256 public pendingWithdrawal;
    uint256 public lastWithdrawalTime;
    bool public confirmedWithdrawal;
    
    constructor() public {
        director = msg.sender;
        partner = 0x36B786f3EC7DE8aC4878980f4B021DE62DDDFF41;
        share = 4;
        funds = 0;
        saleClosed = false;
        withdrawalPhase = 0;
        pendingWithdrawal = 0;
        lastWithdrawalTime = 0;
        confirmedWithdrawal = false;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // If this is the first withdrawal attempt, initialize withdrawal state
        if (withdrawalPhase == 0) {
            withdrawalPhase = 1;
            pendingWithdrawal = this.balance;
            lastWithdrawalTime = now;
            return;
        }
        
        // Phase 2: Confirm withdrawal after 1 hour delay
        if (withdrawalPhase == 1) {
            require(now >= lastWithdrawalTime + 1 hours);
            withdrawalPhase = 2;
            confirmedWithdrawal = true;
            return;
        }
        
        // Phase 3: Execute withdrawal
        if (withdrawalPhase == 2 && confirmedWithdrawal) {
            uint256 withdrawAmount = pendingWithdrawal;
            
            // VULNERABILITY: External call before state cleanup
            // This allows reentrancy after state has been built up across multiple transactions
            director.transfer(withdrawAmount);
            
            // State cleanup happens AFTER external call (vulnerability)
            withdrawalPhase = 0;
            pendingWithdrawal = 0;
            confirmedWithdrawal = false;
            lastWithdrawalTime = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
