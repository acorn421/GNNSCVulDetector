/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. **Added External Call Before State Update**: Introduced `_spender.call()` with `onApprovalReceived()` callback before updating the allowance mapping
 * 2. **Removed Reentrancy Protection**: No guards against reentrant calls during the external callback
 * 3. **State Update After External Call**: The critical `allowance[msg.sender][_spender] = _value` update happens after the external call
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 1. **Transaction 1 (Setup)**: User calls `approve(maliciousContract, 1000)` for legitimate purposes
 * 2. **During Callback**: MaliciousContract's `onApprovalReceived()` is triggered and can:
 *    - Call `approve()` again with different values
 *    - Manipulate the approval state through reentrancy
 *    - Set up conditions for future exploitation
 * 3. **Transaction 2 (Exploitation)**: Later, the malicious contract calls `transferFrom()` using the manipulated allowance state from the previous transaction
 * 
 * **WHY MULTIPLE TRANSACTIONS ARE REQUIRED:**
 * - **State Persistence**: The allowance mapping persists between transactions, creating a window for exploitation
 * - **Callback Timing**: The reentrancy occurs during the callback, but the real exploitation happens in subsequent `transferFrom()` calls
 * - **Sequential Dependency**: The vulnerability depends on the sequence of approve → callback manipulation → transferFrom operations
 * - **Cross-Transaction State**: The manipulated allowance state from Transaction 1 enables unauthorized transfers in Transaction 2
 * 
 * This creates a realistic vulnerability where an attacker can manipulate approval states across multiple transactions, making it difficult to detect with single-transaction analysis tools.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-01-31
*/

pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c >= a && c >= b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract MBCC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        balanceOf[msg.sender] = 58000000000000000;              // Give the creator all initial tokens
        totalSupply = 58000000000000000;                        // Update total supply
        name = "magic box";                                   // Set the name for display purposes
        symbol = 'MBCC';                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address.
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify spender about approval with callback mechanism
        uint size;
        assembly { size := extcodesize(_spender) }
        if(size > 0) {
            // External call before state update - potential reentrancy vector
            bool callSuccess = _spender.call(abi.encodeWithSignature("onApprovalReceived(address,uint256)", msg.sender, _value));
            if(!callSuccess) {
                // Allow approval to continue even if callback fails
                // This creates a window for reentrancy exploitation
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address.
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

}
