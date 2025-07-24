/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability involves:
 * 
 * 1. **External Call Before State Updates**: Added a call to `_to.call()` that attempts to notify the recipient contract via `onTokenReceived()` callback BEFORE updating balances and allowances.
 * 
 * 2. **Stateful Nature**: The vulnerability depends on the persistent state of `balanceOf` and `allowance` mappings. During the external call, these state variables still contain their original values, creating a window for exploitation.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 *    - **During Callback**: The malicious contract's `onTokenReceived()` function calls `transferFrom()` again while the original call is still executing
 *    - **Transaction 2+**: Additional recursive calls can be made before the original state updates complete
 *    - **State Accumulation**: Each recursive call sees the same initial state, allowing multiple withdrawals before balance deduction
 * 
 * 4. **Why Multiple Transactions Are Required**:
 *    - The vulnerability requires the recipient contract to have code (checked via `_to.code.length > 0`)
 *    - The malicious contract needs to be deployed first (Transaction 0)
 *    - The initial `transferFrom()` call (Transaction 1) triggers the callback
 *    - The recursive calls during the callback create additional transaction contexts
 *    - Full exploitation requires the accumulated state changes across these multiple call contexts
 * 
 * 5. **Realistic Implementation**: The callback mechanism is a common pattern in modern token contracts (similar to ERC677/ERC777) making this vulnerability realistic and subtle.
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing external interactions before updating internal state, creating a classic reentrancy attack vector that requires multiple transaction contexts to exploit effectively.
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
    assert(c>=a && c>=b);
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
    function MBCC() public {
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
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		if (_value <= 0) throw; 
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates - VULNERABILITY INJECTION
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Notify recipient contract of incoming transfer
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            if (!callSuccess) {
                // Allow transfer to proceed even if callback fails
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

}
