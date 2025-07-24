/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external callback calls at critical state transition points. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup):** Attacker deploys malicious contract and sets it as freezeCallback
 * **Transaction 2 (Exploit):** Attacker calls freeze() which triggers callbacks, allowing reentrancy during state transitions
 * 
 * **How the vulnerability works:**
 * 1. The function decreases balanceOf[msg.sender] first
 * 2. Then makes external call to onFreezeStart() - REENTRANCY WINDOW
 * 3. During this callback, attacker can call freeze() again with inconsistent state
 * 4. The freezeOf mapping hasn't been updated yet, so checks may pass incorrectly
 * 5. After callback returns, freezeOf is updated
 * 6. Another callback onFreezeComplete() creates second reentrancy window
 * 
 * **Why it requires multiple transactions:**
 * - Attacker must first deploy and register malicious callback contract
 * - The exploit depends on accumulated state changes persisting between transactions
 * - Multiple freeze() calls in sequence can drain more tokens than user actually owns
 * - The vulnerability exploits the gap between balance decrease and freeze amount increase
 * 
 * **Exploitation sequence:**
 * 1. Deploy malicious callback contract
 * 2. Set callback contract address (separate transaction)
 * 3. Call freeze() which triggers reentrancy during callback
 * 4. Malicious contract calls freeze() again before state is fully consistent
 * 5. This can result in freezing more tokens than the user's actual balance
 * 
 * This creates a realistic vulnerability where the attacker needs to orchestrate multiple transactions and the exploit depends on state persistence between calls.
 */
pragma solidity ^0.4.24;
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
        assert(b >=0);
        return a - b;
    }
 
 
    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}

// Declare the IFreezeCallback interface needed for external calls in freeze
interface IFreezeCallback {
    function onFreezeStart(address user, uint256 value) external;
    function onFreezeComplete(address user, uint256 value) external;
}
 
contract bv is SafeMath{
    
    string public name; 
   
    string public symbol;
    
    uint8 public decimals;
    
    uint256 public totalSupply;
    
    address public owner;
 
    mapping (address => uint256) public balanceOf;
   
    mapping (address => mapping (address => uint256)) public allowance;
    
    mapping (address => uint256) public freezeOf;

    // Declare freezeCallback address variable
    address public freezeCallback;
 
   
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
        decimals = decimalUnits;                           
        balanceOf[msg.sender] = initialSupply * 10 ** 18;    
        totalSupply = initialSupply * 10 ** 18;   
        name = tokenName;      
        symbol = tokenSymbol;
        owner = msg.sender;
    }
 
  
    function transfer(address _to, uint256 _value) public {

        assert(_to != 0x0);
                    
        assert(_value > 0);

        assert(balanceOf[msg.sender] >= _value);
 
        assert(balanceOf[_to] + _value >= balanceOf[_to]);
      
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     
      
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
      
        emit Transfer(msg.sender, _to, _value);// Notify anyone listening that this transfer took place
    }
 
   
    function approve(address _spender, uint256 _value) public returns (bool success) {
        assert(_value > 0);
        allowance[msg.sender][_spender] = _value;
        return true;
    }
 

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        
        assert(_to != 0x0);
      
        assert(_value > 0);
       
        assert(balanceOf[_from] >= _value);
       
        assert(balanceOf[_to] + _value >= balanceOf[_to]);
        
        assert(_value <= allowance[_from][msg.sender]);
       
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); 
       
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
      
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        emit Transfer(_from, _to, _value);
        return true;
    }
 

    function burn(uint256 _value) public returns (bool success) {
        
        assert(balanceOf[msg.sender] >= _value);
       
        assert(_value > 0);
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        
        totalSupply = SafeMath.safeSub(totalSupply,_value);
        
        emit Burn(msg.sender, _value);
        return true;
    }
 
  
    function freeze(uint256 _value) public returns (bool success) {
        
        assert(balanceOf[msg.sender] >= _value);
       
        assert(_value > 0);
       
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); 
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before completing all state changes
        // This creates a reentrancy window where state is inconsistent
        if (freezeCallback != address(0)) {
            IFreezeCallback(freezeCallback).onFreezeStart(msg.sender, _value);
        }
        
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); 
        
        // Another external call after state changes - compounds the vulnerability
        if (freezeCallback != address(0)) {
            IFreezeCallback(freezeCallback).onFreezeComplete(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       
        emit Freeze(msg.sender, _value);
        return true;
    }
 
    
    function unfreeze(uint256 _value) public returns (bool success) {
       
        assert(freezeOf[msg.sender] >= _value);
       
        assert(_value > 0); 
     
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value); 
        
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);    
        
        emit Unfreeze(msg.sender, _value);
        return true;
    }
 

    function withdrawEther(uint256 amount) public {
        
        assert(msg.sender == owner);
        
        owner.transfer(amount);
    }
}
