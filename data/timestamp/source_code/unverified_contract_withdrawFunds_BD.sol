/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
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
 * Introduced a stateful multi-transaction timestamp dependence vulnerability by implementing a complex withdrawal window system. The vulnerability requires multiple transactions to exploit because: 1) First transaction initializes the withdrawal window state, 2) Subsequent transactions can exploit timestamp manipulation to bypass the intended 7-day withdrawal periods and 24-hour cooldowns. The vulnerability uses block.timestamp for critical timing calculations, creating opportunities for miners to manipulate timestamps within the ~15-minute tolerance to bypass withdrawal restrictions or reduce penalty amounts. State variables (lastWithdrawalTime, withdrawalWindowStart, totalWithdrawals) persist between transactions and are essential for the exploitation sequence.
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
    
    // The following variables are needed for withdrawFunds
    uint256 public lastWithdrawalTime;
    uint256 public withdrawalWindowStart;
    uint256 public totalWithdrawals;
    
    function PearlBonus() public {
        director = msg.sender;
        partner = 0x36B786f3EC7DE8aC4878980f4B021DE62DDDFF41;
        share = 4;
        funds = 0;
        saleClosed = false;
        lastWithdrawalTime = 0;
        withdrawalWindowStart = 0;
        totalWithdrawals = 0;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Initialize withdrawal window on first call
        if (lastWithdrawalTime == 0) {
            lastWithdrawalTime = block.timestamp;
            withdrawalWindowStart = block.timestamp;
            return; // Exit early, require second transaction
        }
        
        // Check if we're in a valid withdrawal window (every 7 days)
        uint256 currentWindow = (block.timestamp - withdrawalWindowStart) / 7 days;
        uint256 expectedWindow = (lastWithdrawalTime - withdrawalWindowStart) / 7 days;
        
        // Allow withdrawal if we're in the next window
        require(currentWindow > expectedWindow);
        
        // Additional check: ensure at least 24 hours between withdrawals
        require(block.timestamp >= lastWithdrawalTime + 1 days);
        
        // Update state for next withdrawal
        lastWithdrawalTime = block.timestamp;
        totalWithdrawals++;
        
        // Calculate withdrawal amount based on time elapsed
        uint256 timeElapsed = block.timestamp - withdrawalWindowStart;
        uint256 withdrawalAmount = this.balance;
        
        // Reduce amount if withdrawing too frequently (within 48 hours of window opening)
        if (block.timestamp < withdrawalWindowStart + (currentWindow * 7 days) + 2 days) {
            withdrawalAmount = withdrawalAmount / 2; // Penalty for early withdrawal
        }
        
        director.transfer(withdrawalAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
