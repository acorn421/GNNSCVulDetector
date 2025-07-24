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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract before state updates. The vulnerability requires multiple transactions to exploit: 1) Initial setup with frozen tokens, 2) First unfreeze call that triggers callback, 3) Reentrant calls during callback before state updates complete. The external call enables callback-based reentrancy where an attacker can manipulate their contract to re-enter the unfreeze function during the callback, allowing them to unfreeze the same tokens multiple times across different transactions before the state is properly updated. This creates a classic reentrancy scenario where state inconsistencies persist across transaction boundaries, enabling token theft through accumulated frozen balance exploitation.
 */
pragma solidity ^0.4.18;

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal pure {
    if (!assertion) {
      revert();
    }
  }
}

contract CTF is SafeMath{
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
    
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              
        totalSupply = initialSupply;                        
        name = tokenName;                                   
        symbol = tokenSymbol;                               
        decimals = decimalUnits;                            
		owner = msg.sender;
    }
    
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();    
		if (_value <= 0) revert(); 
        if (balanceOf[msg.sender] < _value) revert(); 
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            
        emit Transfer(msg.sender, _to, _value);                   
    }
    
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
		if (_value <= 0) revert(); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();    
		if (_value <= 0) revert(); 
        if (balanceOf[_from] < _value) revert();       
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  
        if (_value > allowance[_from][msg.sender]) revert();     
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            
		if (_value <= 0) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                
        emit Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            
		if (_value <= 0) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                
        emit Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            
		if (_value <= 0) revert(); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to user-controlled contract before state updates
        // This enables callback-based reentrancy across multiple transactions
        if (extcodesize(msg.sender) > 0) {
            msg.sender.call(bytes4(keccak256("onUnfreeze(uint256)")), _value);
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
		
	function withdrawEther(uint256 amount) public {
		if(msg.sender != owner) revert();
		owner.transfer(amount);
	}
			
	function () public payable {
    }
    
    // extcodesize helper for code check (Solidity <0.5.0)
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
