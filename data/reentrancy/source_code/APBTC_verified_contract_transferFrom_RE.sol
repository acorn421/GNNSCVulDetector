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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates but before allowance updates. This creates a reentrancy window where the allowance hasn't been decremented yet, allowing a malicious contract to re-enter and exploit the same allowance multiple times across different transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Victim calls `approve(attackerContract, 1000)` to grant allowance
 * - State: `allowance[victim][attackerContract] = 1000`
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)`
 * - Balance updates occur: `balanceOf[victim] -= 500`, `balanceOf[maliciousContract] += 500`
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - At this point, `allowance[victim][attackerContract]` is still 1000 (not yet decremented)
 * 
 * **Transaction 3 (Reentrancy Exploitation):**
 * - Inside the `onTokenReceived` callback, malicious contract calls `transferFrom(victim, anotherAddress, 500)` again
 * - The allowance check passes because `allowance[victim][attackerContract]` is still 1000
 * - This allows draining more tokens than the original allowance should permit
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The allowance must be pre-established in a separate transaction
 * 2. The vulnerability exploits the state inconsistency between balance updates and allowance decrements
 * 3. The external call provides a window for reentrancy that persists across the transaction boundary
 * 4. Multiple calls are needed to fully exploit the accumulated allowance state
 * 
 * This vulnerability is realistic as it mimics token transfer notification patterns (like ERC777) but implements them insecurely by violating the Checks-Effects-Interactions pattern.
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

  function _assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract APBTC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function APBTC (
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
	if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
	if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
	if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about transfer (potential external call)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // log warning but don't revert to maintain compatibility
            callSuccess; // Do nothing, just to avoid unused variable warning
        }
        
        // Update allowance AFTER external call - VULNERABILITY: Reentrancy window
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }
}
