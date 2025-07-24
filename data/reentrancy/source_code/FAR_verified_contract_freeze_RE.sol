/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to `IFreezeHandler(freezeHandler).onFreeze(msg.sender, _value)` before the state modifications occur.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call happens after input validation but before the critical state updates to `balanceOf` and `freezeOf`.
 * 
 * 3. **Assumes Additional State Variable**: The code assumes a `freezeHandler` address variable exists in the contract that points to an external contract implementing the `IFreezeHandler` interface.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker calls `freeze(100)` with legitimate intention
 * - External call to `freezeHandler.onFreeze()` occurs before state update
 * - Attacker's malicious contract (set as freezeHandler) receives the callback
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - In the `onFreeze()` callback, attacker's contract calls `freeze()` again
 * - Since `balanceOf[attacker]` hasn't been updated yet from Transaction 1, the balance check passes
 * - This allows freezing more tokens than actually owned
 * - The attacker can repeat this across multiple transactions to accumulate excessive frozen amounts
 * 
 * **Transaction 3+ - Accumulation:**
 * - Attacker continues the pattern across multiple transactions
 * - Each transaction builds upon the inconsistent state from previous transactions
 * - The vulnerability compounds as frozen amounts accumulate beyond actual balance
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the accumulated `freezeOf` values across multiple transactions, where each transaction leaves the contract in an inconsistent state.
 * 
 * 2. **Time-Based Exploitation**: The attacker needs multiple transactions to build up significant frozen amounts that exceed their actual balance, making the exploit economically viable.
 * 
 * 3. **Cross-Transaction State Dependency**: Each subsequent transaction depends on the inconsistent state left by previous transactions, creating a cascading effect that's impossible to achieve in a single transaction.
 * 
 * 4. **Realistic Attack Pattern**: Real attackers would likely perform this across multiple blocks to avoid detection and maximize the exploit's effectiveness.
 * 
 * The vulnerability is subtle and realistic because external freeze notifications are common in DeFi protocols for integration with other systems, making the external call placement seem legitimate while creating a dangerous reentrancy opportunity.
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
}

interface IFreezeHandler {
    function onFreeze(address addr, uint256 value) external;
}

contract FAR is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    address public freezeHandler;

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
        Transfer(msg.sender, _to, _value);                  
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
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();          
		if (_value <= 0) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        totalSupply = SafeMath.safeSub(totalSupply,_value);                               
        Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		if (_value <= 0) revert();
        
        // Notify external freeze handler before state updates (vulnerability)
        if (freezeHandler != address(0)) {
            IFreezeHandler(freezeHandler).onFreeze(msg.sender, _value);
        }
        
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                             
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();           
		if (_value <= 0) revert(); 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                     
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
	
	function withdrawEther(uint256 amount) public {
		if(msg.sender != owner) revert();
		owner.transfer(amount);
	}
	
	function() public payable {
    }
	
}
