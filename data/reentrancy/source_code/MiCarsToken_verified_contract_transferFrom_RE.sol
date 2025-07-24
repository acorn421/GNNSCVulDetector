/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _amount))` after the balance/allowance checks but before state updates
 * 2. The call is made only if the recipient is a contract (`_to.code.length > 0`)
 * 3. The function continues execution regardless of the external call's success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker gets approval for tokens (e.g., 1000 tokens) via `approve()` function
 * 2. **Transaction 2**: Attacker calls `transferFrom()` with a malicious recipient contract
 * 3. **Reentrancy**: The malicious recipient contract's `onTokenReceived` callback is triggered before state updates
 * 4. **Reentrant Call**: Within the callback, the malicious contract calls `transferFrom()` again with the same allowance
 * 5. **State Exploitation**: Since the original allowance hasn't been decremented yet, the second call succeeds
 * 6. **Result**: Attacker transfers more tokens than they were approved for
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on having a pre-existing allowance (set in Transaction 1)
 * - The allowance state persists between transactions and is the foundation for the attack
 * - The reentrancy can only be triggered when transferring to a contract address
 * - The exploit requires the accumulated state (allowance) from previous transactions to be effective
 * - Without the prior allowance setup, the reentrancy attack would fail the initial balance/allowance checks
 * 
 * **Realistic Nature:**
 * - Token transfer notifications are common in DeFi protocols
 * - The pattern appears as a legitimate feature enhancement
 * - The vulnerability follows the classic Checks-Effects-Interactions pattern violation
 * - The code maintains full functionality while introducing a subtle but critical security flaw
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
            owner.transfer(msg.value);
            owner.transfer(address(this).balance);
            owner=_newowner;
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
        
        uint256 senderBalance = balances[msg.sender];
        if (senderBalance >= _value && _value > 0) {
            senderBalance -= _value;
            balances[msg.sender] = senderBalance;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    
    function mintTo(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
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
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             // Notify recipient contract if it has code (vulnerable external call before state updates)
             uint size;
             assembly { size := extcodesize(_to) }
             if (size > 0) {
                 _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _amount));
             }
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
         emit Approval(msg.sender, _spender, _amount);
         
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
        
        uint256 numTokens = msg.value * (1000 / totalTokens);
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        emit Transfer(0, msg.sender, numTokens);
    }
}
