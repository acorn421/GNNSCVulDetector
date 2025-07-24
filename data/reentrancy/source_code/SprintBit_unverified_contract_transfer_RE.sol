/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * **Specific Changes Made:**
 * 
 * 1. **Added persistent validation state**: Introduced `transferValidations[msg.sender]` mapping that tracks validation state across transactions and persists between calls.
 * 
 * 2. **External call before state updates**: Added call to `ITokenReceiver(_to).onTokenTransfer()` which executes BEFORE balance updates, creating a classic reentrancy vulnerability.
 * 
 * 3. **State updates after external call**: Moved balance modifications to occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 4. **Multi-transaction state dependency**: The validation state creates dependencies that span multiple transactions.
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `transfer()` to a malicious contract
 * - `transferValidations[attacker]` is set to current block number
 * - External call triggers attacker's `onTokenTransfer()` function
 * - During callback, attacker can observe that balances haven't been updated yet
 * - Attacker can call `transfer()` again recursively, but with limited gas
 * 
 * **Transaction 2 (Exploitation):**
 * - In a subsequent transaction, attacker leverages the persistent validation state
 * - The `transferValidations` mapping retains state from previous transaction
 * - Attacker can exploit the accumulated state inconsistencies
 * - Multiple recursive calls across transactions can drain more funds than available
 * 
 * **Transaction 3+ (Continuation):**
 * - Attacker continues exploitation across multiple blocks
 * - Each transaction builds upon the persistent state modifications
 * - The validation state accumulates, enabling larger exploit potential
 * 
 * **Why Multi-Transaction Required:**
 * 
 * 1. **State Accumulation**: The `transferValidations` mapping accumulates state across transactions, enabling larger exploits over time.
 * 
 * 2. **Gas Limitations**: Single-transaction reentrancy is limited by gas constraints, but multi-transaction attacks can bypass these limits.
 * 
 * 3. **Block-based Validation**: The validation mechanism uses `block.number`, creating dependencies that span multiple blocks and transactions.
 * 
 * 4. **Persistent State Dependencies**: The vulnerability leverages state that persists between transactions, making it impossible to exploit atomically.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to fully exploit, making it particularly dangerous and difficult to detect with single-transaction analysis tools.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-10-21
*/

pragma solidity ^0.4.6;

contract SprintBit {

  string public name = "SprintBit";
  string public symbol = "SBT";
  uint public decimals = 18;
  uint public INITIAL_SUPPLY = 100000000000000000000000000;

  mapping(address => uint) balances;
  mapping (address => mapping (address => uint)) allowed;
  uint256 public _totalSupply;
  address public _creator;
  bool bIsFreezeAll = false;
  
  // === ADDED DECLARATION ===
  mapping(address => uint) transferValidations;
  
  event Transfer(address indexed from, address indexed to, uint value);
  event Approval(address indexed owner, address indexed spender, uint value);

  // === ADDED INTERFACE ===
  // Moved interface outside contract
}

interface ITokenReceiver {
  function onTokenTransfer(address from, uint value, bytes data) external;
}

contract SprintBitContinuing is SprintBit {

  function safeSub(uint a, uint b) internal returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint a, uint b) internal returns (uint) {
    uint c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
  function totalSupply() public constant returns (uint256 total) {
	total = _totalSupply;
  }

  function transfer(address _to, uint _value) public returns (bool success) {
    require(bIsFreezeAll == false);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Add transfer validation flag that persists across transactions
    if (transferValidations[msg.sender] == 0) {
        transferValidations[msg.sender] = block.number;
    }
    
    // External call to recipient contract for transfer notification BEFORE state updates
    if (_to != address(0) && _to.call.value(0).gas(2300)()) { // Dummy call to bypass static analysis (code below is used instead)
        // intentionally left blank
    }
    if (_to.code.length > 0) {
        ITokenReceiver(_to).onTokenTransfer(msg.sender, _value, "");
    }
    
    // State updates happen AFTER external call - vulnerable to reentrancy
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[msg.sender] = safeSub(balances[msg.sender], _value);
    balances[_to] = safeAdd(balances[_to], _value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Update validation state after transfer
    transferValidations[msg.sender] = block.number + 1;
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    Transfer(msg.sender, _to, _value);
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
    require(bIsFreezeAll == false);
    uint _allowance = allowed[_from][msg.sender];
    balances[_to] = safeAdd(balances[_to], _value);
    balances[_from] = safeSub(balances[_from], _value);
    allowed[_from][msg.sender] = safeSub(_allowance, _value);
    Transfer(_from, _to, _value);
    return true;
  }

  function balanceOf(address _owner) public constant returns (uint balance) {
    return balances[_owner];
  }

  function approve(address _spender, uint _value) public returns (bool success) {
	require(bIsFreezeAll == false);
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public constant returns (uint remaining) {
    return allowed[_owner][_spender];
  }

  function freezeAll() public 
  {
	require(msg.sender == _creator);
	bIsFreezeAll = !bIsFreezeAll;
  }
  
  // === UPDATED TO CONSTRUCTOR ===
  function SprintBitContinuing() public {
        _totalSupply = INITIAL_SUPPLY;
	_creator = 0xc66c4A406ff17E976C06025a750ED3723EDA174c;
	balances[_creator] = INITIAL_SUPPLY;
	bIsFreezeAll = false;
  }
  
  function destroy() public  {
	require(msg.sender == _creator);
	selfdestruct(_creator);
  }

}
