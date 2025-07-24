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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduces `pendingOwner` and `ownershipTransferAmount` to track ownership transfer state across transactions
 * 
 * 2. **Specific Changes Made**:
 *    - Added intermediate state tracking with `pendingOwner` and `ownershipTransferAmount`
 *    - Moved ownership assignment to after external calls
 *    - Added conditional logic that depends on persistent state values
 *    - Created a multi-step process where state is checked and modified incrementally
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `changeOwner()` with sufficient ETH
 *    - **During Reentrancy**: When `owner.transfer()` is called, if the current owner is a malicious contract, it can:
 *      - Re-enter `changeOwner()` with a different `_newowner` address
 *      - Modify the `pendingOwner` state variable during the first call's execution
 *      - The first call's final ownership check fails due to state manipulation
 *    - **Transaction 2+**: Attacker can exploit the inconsistent state where payment was made but ownership wasn't transferred, allowing multiple claims or manipulation of the transfer process
 * 
 * 4. **Why Multi-Transaction Required**:
 *    - The vulnerability requires the attacker to first establish the `pendingOwner` state
 *    - Then exploit the reentrancy during external calls to manipulate this state
 *    - Finally, the state inconsistency persists between transactions, enabling further exploitation
 *    - Single-transaction exploitation is prevented by the state checks, but multi-transaction sequences can bypass these protections
 * 
 * 5. **Stateful Nature**:
 *    - The `pendingOwner` and `ownershipTransferAmount` variables persist between transactions
 *    - The vulnerability depends on accumulated state changes across multiple calls
 *    - Each transaction can partially modify the state, enabling complex attack scenarios
 * 
 * This creates a realistic reentrancy vulnerability that mimics real-world patterns where complex state management during external calls can be exploited across multiple transactions.
 */
pragma solidity ^0.4.19;

/// @title  MedicalChain token presale - https://medicalchain.com/ (MED) - crowdfunding code
/// Whitepaper:
///  https://medicalchain.com/Medicalchain-Whitepaper-EN.pdf

contract MedicalChainToken {
    string public name = "MedToken";
    string public symbol = "MED";
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

    // Variables used for vulnerable changeOwner logic
    address public pendingOwner;
    uint256 public ownershipTransferAmount;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Migrate(address indexed _from, address indexed _to, uint256 _value);
    event Refund(address indexed _from, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
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
            // Start ownership transfer process
            pendingOwner = _newowner;
            ownershipTransferAmount = msg.value;
            
            // Transfer payment to current owner - vulnerable to reentrancy
            owner.transfer(msg.value);
            
            // Transfer remaining contract balance - second vulnerable call
            if (this.balance > 0) {
                owner.transfer(this.balance);
            }
            
            // Complete ownership transfer only after all transfers
            if (pendingOwner == _newowner && ownershipTransferAmount == msg.value) {
                owner = pendingOwner;
                pendingOwner = address(0);
                ownershipTransferAmount = 0;
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
        
        uint256 senderBalance = balances[msg.sender]; // replaced 'var' with explicit type
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
        
        uint256 numTokens = msg.value * (1000) / totalTokens; // replaced 'var' and float literal
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}
