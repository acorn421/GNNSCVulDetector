/*
 * ===== SmartInject Injection Details =====
 * Function      : closeSale
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added State Variable Dependency**: The function now relies on a `pendingCloseTimestamp` state variable that must be set in a previous transaction before the sale can actually be closed.
 * 
 * 2. **Multi-Transaction Requirement**: 
 *    - First transaction: Sets `pendingCloseTimestamp = block.timestamp` and returns false
 *    - Second transaction: Must wait at least 60 seconds AND occur during a specific time window (first half of every 256-second cycle)
 * 
 * 3. **Timestamp Manipulation Vulnerability**: The function uses `block.timestamp % 256 < 128` to create predictable time windows. Miners can manipulate block timestamps within the ~15-second tolerance to:
 *    - Prevent legitimate close attempts by ensuring timestamps fall in the second half of the cycle
 *    - Enable their own transactions by manipulating timestamps to fall in the first half
 *    - Control the exact timing of when sales can be closed
 * 
 * 4. **Exploitation Scenario**:
 *    - Transaction 1: Director calls closeSale() → sets pendingCloseTimestamp, returns false
 *    - Miner manipulation: Manipulate subsequent block timestamps to prevent legitimate closes
 *    - Transaction 2: Attacker or miner calls closeSale() during manipulated favorable time window
 *    - Result: Control over when the sale can be closed, potentially affecting crowdsale economics
 * 
 * 5. **State Persistence**: The `pendingCloseTimestamp` state persists between transactions, creating a stateful vulnerability that requires multiple calls to exploit.
 * 
 * This vulnerability is realistic because it mimics real-world patterns where developers add time-based restrictions for security or business logic, but inadvertently create timestamp manipulation attack vectors.
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
    uint256 public pendingCloseTimestamp; // Added missing variable declaration
    
    constructor() public { // Updated from function PearlBonus() to constructor()
        director = msg.sender;
        partner = 0x36B786f3EC7DE8aC4878980f4B021DE62DDDFF41;
        share = 4;
        funds = 0;
        saleClosed = false;
        pendingCloseTimestamp = 0; // Initialize
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store the close request timestamp for delayed execution
        if (pendingCloseTimestamp == 0) {
            pendingCloseTimestamp = block.timestamp;
            return false; // Close request initiated but not executed yet
        }
        
        // Allow closing only during specific time windows (every 256 seconds)
        // This creates predictable timing that miners can manipulate
        require((block.timestamp - pendingCloseTimestamp) >= 60); // 1 minute delay
        require(block.timestamp % 256 < 128); // Only closeable in first half of each 256-second window
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Lock the crowdsale
        saleClosed = true;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        pendingCloseTimestamp = 0; // Reset for future use
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
