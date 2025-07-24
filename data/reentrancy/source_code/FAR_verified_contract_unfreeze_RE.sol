/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller's contract before state updates. This creates a classic reentrancy pattern where:
 * 
 * 1. **State Persistence**: The freezeOf and balanceOf mappings maintain state between transactions
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls unfreeze, which triggers the external call back to their contract
 *    - During the callback, the attacker can call unfreeze again while the original call's state hasn't been updated yet
 *    - This allows multiple unfreezes using the same frozen balance before the state is properly decremented
 * 3. **Exploitation Sequence**:
 *    - Attacker freezes tokens normally
 *    - Attacker calls unfreeze() which triggers callback to their malicious contract
 *    - In the callback, attacker calls unfreeze() again (reentrancy)
 *    - The second call sees the original frozen balance (not yet updated)
 *    - Both calls succeed, effectively unfreezing more tokens than were originally frozen
 * 4. **Why Multi-Transaction**: The vulnerability requires the attacker to have previously frozen tokens (Transaction 1), then exploit the reentrancy during unfreeze (Transaction 2 with internal reentrant calls)
 * 
 * The external call uses a low-level call to invoke an "onUnfreeze" callback function if it exists on the caller's contract, creating the reentrancy window. This is realistic as many DeFi protocols implement callback mechanisms for token operations.
 */
pragma solidity ^0.4.18;

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
contract FAR is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Freeze(address indexed from, uint256 value);
    event Unfreeze(address indexed from, uint256 value);

    function FAR(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              
        totalSupply = initialSupply;                        
        name = tokenName;                                   
        symbol = tokenSymbol;                               
        decimals = decimalUnits;                           
		owner = msg.sender;
    }

    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                  
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                           
        Transfer(msg.sender, _to, _value);                  
    }

    function approve(address _spender, uint256 _value)
        returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        if (_value > allowance[_from][msg.sender]) throw;     
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;          
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        totalSupply = SafeMath.safeSub(totalSupply,_value);                               
        Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                             
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;           
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external contract about unfreeze - VULNERABILITY: External call before state update
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // External call succeeded, continue with unfreezing
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                     
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
	
	function withdrawEther(uint256 amount) {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	function() payable {
    }
	
}