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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification mechanism that makes an external call before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added recipient notification mechanism with external call to `_to.call()` for contract recipients
 * 2. Moved the allowance update (`allowed[_from][msg.sender] -= _amount`) to occur AFTER the external call
 * 3. Added revert logic if the notification fails, creating additional state manipulation opportunities
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Setup Transaction**: Attacker sets up allowance and deploys malicious recipient contract
 * 2. **Trigger Transaction**: Victim calls transferFrom() with malicious contract as recipient
 * 3. **Reentrancy Exploitation**: During the external call, the malicious contract can:
 *    - Re-enter transferFrom() with the same allowance (not yet decremented)
 *    - Drain additional tokens before the original allowance is updated
 *    - Accumulate multiple transfers with the same allowance across re-entrant calls
 * 
 * **Why Multi-Transaction Required:**
 * - The allowance must be set up in a previous transaction (approve() call)
 * - The attack requires the victim to initiate transferFrom() to trigger the callback
 * - The malicious contract exploits the time window between balance updates and allowance updates
 * - Multiple re-entrant calls can accumulate to drain far more tokens than the original allowance permitted
 * - The vulnerability depends on the persistent state of allowances between transactions
 * 
 * **State Persistence Impact:**
 * - Balance changes persist between transactions and accumulate damage
 * - Allowance state is manipulated across multiple calls within the same transaction
 * - The vulnerability compounds with each successful re-entrant call
 * - Requires coordination between setup (approve) and exploitation (transferFrom) transactions
 * 
 * This creates a realistic vulnerability where the attacker must coordinate multiple transactions and the damage accumulates through state persistence, making it a genuine multi-transaction, stateful reentrancy vulnerability.
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
             balances[_from] -= _amount;
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             balances[_to] += _amount;
             
             // Notify recipient contract about token reception
             uint256 size;
             assembly { size := extcodesize(_to) }
             if (size > 0) {
                 // External call to recipient contract before updating allowance
                 bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount);
                 if (!callSuccess) {
                     // If notification fails, revert the transfer
                     balances[_from] += _amount;
                     balances[_to] -= _amount;
                     return false;
                 }
             }
             
             // Update allowance after external call - VULNERABILITY!
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
             allowed[_from][msg.sender] -= _amount;
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
        emit Transfer(0x0, msg.sender, numTokens);
    }
}
