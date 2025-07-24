/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending transfers tracking system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Director initiates a transfer of >1000 tokens, which gets marked as pending and tracked in state variables (pendingTransfers mapping and totalPendingAmount).
 * 
 * **Transaction 2**: When director calls transfer again for the same address, the function attempts to complete the pending transfer first. During the external call to pearl.transfer(), a malicious contract at _send address can re-enter the transfer function.
 * 
 * **Exploitation Sequence**:
 * 1. First call: transfer(maliciousContract, 2000) - sets pendingTransfers[maliciousContract] = 2000
 * 2. Second call: transfer(maliciousContract, 1000) - triggers completion of pending transfer
 * 3. During pearl.transfer() call, maliciousContract.fallback() re-enters transfer()
 * 4. Re-entrance finds pendingTransfers[maliciousContract] still set to 2000 (not yet cleared)
 * 5. Malicious contract can manipulate the pending state before original execution completes
 * 6. Results in double-spending or state corruption across multiple transactions
 * 
 * The vulnerability is stateful because it depends on the pendingTransfers mapping persisting between transactions, and multi-transaction because the exploit requires at least two separate calls to the transfer function to set up and trigger the vulnerable state.
 */
pragma solidity ^0.4.18;

interface OysterPearl {
    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _amount) public returns (bool success);
}

contract PearlBonus {
    address public pearlContract = 0x1844b21593262668B7248d0f57a220CaaBA46ab9;
    OysterPearl pearl = OysterPearl(pearlContract);
    
    address public director;
    address public partner;
    uint8 public share;
    uint256 public funds;
    bool public saleClosed;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Added state for tracking pending transfers
    mapping(address => uint256) public pendingTransfers;
    uint256 public totalPendingAmount;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
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
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transfer(address _send, uint256 _amount) public onlyDirector {
        // Check if there's already a pending transfer for this address
        if (pendingTransfers[_send] > 0) {
            // Complete the pending transfer first
            uint256 pendingAmount = pendingTransfers[_send];
            pendingTransfers[_send] = 0;
            totalPendingAmount -= pendingAmount;
            
            // External call BEFORE state is fully updated - reentrancy opportunity
            pearl.transfer(_send, pendingAmount);
            
            // Continue with current transfer
            pearl.transfer(_send, _amount);
        } else {
            // For new transfers, mark as pending if amount > 1000 tokens
            if (_amount > 1000) {
                pendingTransfers[_send] = _amount;
                totalPendingAmount += _amount;
                
                // External call with pending state still active
                pearl.transfer(_send, _amount);
                
                // State cleanup happens after external call - vulnerable window
                pendingTransfers[_send] = 0;
                totalPendingAmount -= _amount;
            } else {
                // Direct transfer for small amounts
                pearl.transfer(_send, _amount);
            }
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
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
