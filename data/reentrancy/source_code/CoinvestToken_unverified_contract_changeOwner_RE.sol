/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOwner
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by implementing a partial payment accumulation system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. **Added State Variables**: `partialPayments` mapping to track accumulated payments, `ownershipPending` to track pending ownership transfers, and `ownershipQueue` array to manage the queue.
 * 
 * 2. **Partial Payment Accumulation**: The function now allows users to make multiple smaller payments that accumulate toward the ownership threshold, creating persistent state between transactions.
 * 
 * 3. **Critical Reentrancy Window**: The external call `owner.transfer(partialPayments[msg.sender])` occurs BEFORE state cleanup, allowing reentrancy to manipulate the accumulated payment state.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker makes partial payment (e.g., 600 ETH of required 1000 ETH), payment is recorded in `partialPayments`
 * - **Transaction 2**: Attacker makes another partial payment (e.g., 400 ETH), reaching the threshold
 * - **During Transaction 2**: When `owner.transfer()` is called, the attacker's contract can re-enter and make additional payments to `partialPayments[msg.sender]` before the state is reset
 * - **Result**: The accumulated payment state is manipulated during the external call, potentially allowing the attacker to drain more funds or manipulate the ownership queue
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability depends on the `partialPayments` mapping accumulating value across multiple transactions
 * 2. **Timing Dependency**: The reentrancy window only exists when the accumulated payment reaches the threshold, requiring prior transactions to build up the state
 * 3. **Queue Manipulation**: The ownership queue and pending status create complex state dependencies that require multiple interactions to exploit effectively
 * 
 * This creates a realistic scenario where the vulnerability cannot be exploited in a single transaction but requires building up state through multiple calls, making it much more subtle and harder to detect in automated analysis.
 */
pragma solidity ^0.4.19;


/// @title  Coinvest token presale - https://coinve.st (COIN) - crowdfunding code
/// Whitepaper:
///  https://docs.google.com/document/d/1ePI50Vd9MGdkPnH0KdVuhTOOSiqmnE7WteGDtG10GuE
/// 

contract CoinvestToken {
    string public name = "Coinvest";
    string public symbol = "COIN";
    uint8 public constant decimals = 18;  
    address public owner;

    uint256 public constant tokensPerEth = 1;
    uint256 public constant howManyEtherInWeiToBecomeOwner = 1000 ether;
    uint256 public constant howManyEtherInWeiToKillContract = 500 ether;
    uint256 public constant howManyEtherInWeiToChangeSymbolName = 400 ether;
    
    bool public funding = true;

    // The current total token supply.
    uint256 totalTokens = 1000;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Migrate(address indexed _from, address indexed _to, uint256 _value);
    event Refund(address indexed _from, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function CoinvestToken() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    function changeNameSymbol(string _name, string _symbol) payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            name = _name;
            symbol = _symbol;
        }
    }
    
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) private partialPayments;
    mapping(address => bool) private ownershipPending;
    address[] private ownershipQueue;

    function changeOwner (address _newowner) payable external
    {
        // Allow partial payments to accumulate toward ownership
        if (msg.value > 0) {
            partialPayments[msg.sender] += msg.value;
        }
        
        // Check if accumulated payment meets the threshold
        if (partialPayments[msg.sender] >= howManyEtherInWeiToBecomeOwner && _newowner != address(0))
        {
            // Add to pending ownership queue if not already pending
            if (!ownershipPending[msg.sender]) {
                ownershipQueue.push(msg.sender);
                ownershipPending[msg.sender] = true;
            }
            
            // External call to current owner before state changes - creates reentrancy window
            owner.transfer(partialPayments[msg.sender]);
            
            // Vulnerability: State updates happen after external call
            // This allows reentrancy to manipulate the accumulated state
            uint256 remainingBalance = this.balance;
            if (remainingBalance > 0) {
                owner.transfer(remainingBalance);
            }
            
            // Reset the partial payment tracking
            partialPayments[msg.sender] = 0;
            ownershipPending[msg.sender] = false;
            
            // Remove from queue (simplified - just mark as processed)
            for (uint i = 0; i < ownershipQueue.length; i++) {
                if (ownershipQueue[i] == msg.sender) {
                    ownershipQueue[i] = ownershipQueue[ownershipQueue.length - 1];
                    ownershipQueue.length--;
                    break;
                }
            }
            
            // Finally update the owner
            owner = _newowner;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }

    function killContract () payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToKillContract)
        {
            selfdestruct(owner);
        }
    }
    /// @notice Transfer `_value` tokens from sender's account
    /// `msg.sender` to provided account address `_to`.
    /// @notice This function is disabled during the funding.
    /// @dev Required state: Operational
    /// @param _to The address of the tokens recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
        var senderBalance = balances[msg.sender];
        if (senderBalance >= _value && _value > 0) {
            senderBalance -= _value;
            balances[msg.sender] = senderBalance;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    
    function mintTo(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
    }
    

    function totalSupply() external constant returns (uint256) {
        return totalTokens;
    }

    function balanceOf(address _owner) external constant returns (uint256) {
        return balances[_owner];
    }


    function transferFrom(
         address _from,
         address _to,
         uint256 _amount
     ) public returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             return true;
         } else {
             return false;
         }
  }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         
         return true;
     }
// Crowdfunding:

    /// @notice Create tokens when funding is active.
    /// @dev Required state: Funding Active
    /// @dev State transition: -> Funding Success (only if cap reached)
    function () payable external {
        // Abort if not in Funding Active state.
        // The checks are split (instead of using or operator) because it is
        // cheaper this way.
        if (!funding) revert();
        
        // Do not allow creating 0 or more than the cap tokens.
        if (msg.value == 0) revert();
        
        var numTokens = msg.value * (1000.0/totalTokens);
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}