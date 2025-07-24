/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOwner
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
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Introduced `_newowner.call()` to notify the new owner before any state changes occur, creating a reentrancy entry point.
 * 
 * 2. **Moved Critical State Updates After External Call**: The owner transfer, balance transfer, and owner assignment now happen after the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Created Multi-Transaction Exploitation Vector**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls `changeOwner` with a malicious contract address that has the `onOwnershipTransferred` function
 *    - **Transaction 2 (Reentrant)**: During the external call, the malicious contract can call `changeOwner` again with different parameters, potentially draining funds or manipulating ownership
 *    - **Transaction 3+**: Additional reentrant calls can continue to manipulate state before the original transaction completes
 * 
 * 4. **Stateful Persistence**: The vulnerability persists across transactions because:
 *    - The contract balance and owner state remain in an inconsistent state between calls
 *    - Multiple ownership changes can be initiated simultaneously
 *    - Funds can be drained across multiple reentrant calls before ownership is finalized
 * 
 * 5. **Multi-Transaction Exploitation Scenario**:
 *    - Attacker deploys a malicious contract that implements `onOwnershipTransferred`
 *    - In `onOwnershipTransferred`, the malicious contract calls `changeOwner` again with a different address
 *    - This creates a chain of reentrant calls where each call can transfer funds before the previous call completes
 *    - The ownership state becomes inconsistent as multiple ownership changes are processed simultaneously
 *    - Each reentrant call can drain contract funds before the owner variable is updated
 * 
 * This vulnerability is realistic as it mimics common patterns where contracts notify external parties of state changes, but the notification happens before the state is actually updated, creating a window for reentrancy exploitation that spans multiple transactions.
 */
pragma solidity ^0.4.19;


/// @title  MiCars Token internal presale - https://micars.io (MCR) - crowdfunding code
/// Whitepaper:
///  https://www.micars.io/wp-content/uploads/2017/12/WhitePaper-EN.pdf


contract MiCarsToken {
    string public name = "MiCars Token";
    string public symbol = "MCR";
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

    function MiCarsToken() public {
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
    
    
    function changeOwner (address _newowner) payable external
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Call the new owner to notify them of ownership change
            // This allows the new owner to perform setup operations
            if (_newowner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
                // State updated after external call - vulnerable to reentrancy
                owner.transfer(msg.value);
                owner.transfer(this.balance);
                owner=_newowner;
            }
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