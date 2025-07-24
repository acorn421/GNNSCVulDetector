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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Introduced a call to the recipient address using `onTokenReceived` pattern, which is common in modern token standards for transfer notifications.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: Moved critical state updates (balanceOf[_from] and allowance updates) to occur AFTER the external call, creating a reentrancy window.
 * 
 * 3. **Preserved Functionality**: The function still performs all intended operations and maintains the same signature and basic logic flow.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup (Transaction 1):**
 * - Attacker gets approval for a large allowance from victim
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * 
 * **Phase 2 - Exploitation (Transactions 2-N):**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - The malicious contract's `onTokenReceived` function is called BEFORE the allowance is decremented
 * - Inside `onTokenReceived`, the malicious contract calls `transferFrom` again with the same allowance
 * - This creates a chain where the same allowance can be used multiple times across different transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance state persists between transactions and is only decremented after the external call
 * 2. **Accumulated Exploitation**: Each transaction in the attack chain exploits the same allowance value, requiring multiple calls to drain significant funds
 * 3. **Realistic Attack Vector**: Real-world exploitation would involve multiple transactions to avoid gas limits and maximize extracted value
 * 
 * **Critical Vulnerability Elements:**
 * - The external call happens before allowance is decremented
 * - The same allowance can be exploited multiple times
 * - State changes from previous transactions enable continued exploitation
 * - The vulnerability compounds across multiple transaction calls
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
 
contract bv is SafeMath{
    
    string public name; 
   
    string public symbol;
    
    uint8 public decimals;
    
    uint256 public totalSupply;
    
    address public owner;
 
    mapping (address => uint256) public balanceOf;
   
    mapping (address => mapping (address => uint256)) public allowance;
    
    mapping (address => uint256) public freezeOf;
 
   
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
       
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // First update the recipient's balance to maintain apparent correctness
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // External call to recipient - potential reentrancy point
        // Common pattern for token transfer notifications
        if (isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call result to maintain functionality
        }
        
        // VULNERABLE: State updates happen after external call
        // This allows reentrancy to exploit the same allowance multiple times
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); 
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
        
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); 
       
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

    // Helper function to detect if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
