/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance. This creates a vulnerability window where:
 * 
 * 1. **State Persistence**: The balances are updated but allowance remains unchanged during the external call
 * 2. **Multi-Transaction Exploitation**: An attacker can deploy a malicious contract that receives tokens and immediately calls transferFrom again in the onTokenReceived callback
 * 3. **Exploitation Flow**:
 *    - Transaction 1: Attacker calls transferFrom with malicious contract as _to
 *    - During external call: Malicious contract receives onTokenReceived callback
 *    - Transaction 2: Within callback, malicious contract calls transferFrom again before allowance is decremented
 *    - The persistent state (unchanged allowance) allows multiple transfers using the same allowance
 * 
 * The vulnerability requires multiple function calls across the callback mechanism and exploits the fact that state changes (balance updates) persist while critical state (allowance) remains unmodified until after the external call completes.
 */
pragma solidity ^0.4.18;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract WIN {
    
    using SafeMath for uint256;
    
    uint256 constant private MAX_UINT256 = 2**256 - 1;

    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed _from, uint256 value);

    constructor(uint256 _initialSupply, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {
        name = _tokenName;                                   
        symbol = _tokenSymbol;
        decimals = _decimalUnits;                            
        totalSupply = _initialSupply;                        
        balanceOf[msg.sender] = _initialSupply;
        owner = msg.sender;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
            // Test validity of the address '_to':
        require(_to != 0x0);
            // Test positiveness of '_value':
		require(_value > 0);
		    // Check the balance of the sender:
        require(balanceOf[msg.sender] >= _value);
            // Check for overflows:
        require(balanceOf[_to] + _value >= balanceOf[_to]); 
            // Update balances of msg.sender and _to:
        balanceOf[msg.sender] = SafeMath.sub(balanceOf[msg.sender], _value);                     
        balanceOf[_to] = SafeMath.add(balanceOf[_to], _value);                            
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
            // Test validity of the address '_to':
        require(_to != 0x0);
            // Test positiveness of '_value':
		require(_value > 0);
		    // Check the balance of the sender:
        require(balanceOf[msg.sender] >= _value);
            // Check for overflows:
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balanceOf[_to] + _value >= balanceOf[_to]); 
            // Check allowance's sufficiency:
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances of _from and _to:
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.sub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.add(balanceOf[_to], _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        if (_to != tx.origin) {
            // External call to recipient before updating allowance
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            require(callSuccess, "Token receive notification failed");
        }
        
        // Update allowance AFTER external call - vulnerability window
        require(allowance[_from][msg.sender] < MAX_UINT256);
        allowance[_from][msg.sender] = SafeMath.sub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
            // Test positiveness of '_value':
		require(_value > 0); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
            // Check msg.sender's balance sufficiency:
        require(balanceOf[msg.sender] >= _value);           
            // Test positiveness of '_value':
		require(_value > 0); 
        balanceOf[msg.sender] = SafeMath.sub(balanceOf[msg.sender], _value);                    
        totalSupply = SafeMath.sub(totalSupply,_value);                              
        emit Burn(msg.sender, _value);
        return true;
    }
            
}