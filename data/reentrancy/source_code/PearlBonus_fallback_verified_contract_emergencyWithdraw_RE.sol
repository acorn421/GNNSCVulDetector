/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This function introduces a reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability exists because the function makes an external call before properly updating all state variables. An attacker must: 1) First call emergencyWithdraw() to set up the pending state, 2) Use a malicious contract to re-enter during the external call, 3) The reentrant call can bypass the pending check due to improper state management, allowing multiple withdrawals. The vulnerability is stateful as it depends on the emergencyWithdrawalPending mapping state persisting between transactions.
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
    // === FALLBACK INJECTION: Reentrancy ===
    // mappings moved from inside constructor to contract scope
    mapping(address => uint256) public emergencyWithdrawals;
    mapping(address => bool) public emergencyWithdrawalPending;
    // === END FALLBACK INJECTION ===
    
    function PearlBonus() public {
        director = msg.sender;
        partner = 0x36B786f3EC7DE8aC4878980f4B021DE62DDDFF41;
        share = 4;
        funds = 0;
        saleClosed = false;
    }
    
    modifier onlyDirector {
        // Only the director is permitted
        require(msg.sender == director);
        _;
    }
    
    /**
     * Emergency withdrawal function for contract maintenance
     */
    function emergencyWithdraw(uint256 _amount) public onlyDirector {
        require(_amount > 0);
        require(!emergencyWithdrawalPending[msg.sender]);
        
        // Set pending flag first
        emergencyWithdrawalPending[msg.sender] = true;
        
        // Track withdrawal amount
        emergencyWithdrawals[msg.sender] += _amount;
        
        // External call before state update (reentrancy vulnerability)
        if (msg.sender.call.value(_amount)()) {
            // Only reset flag after successful transfer
            emergencyWithdrawalPending[msg.sender] = false;
        }
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
