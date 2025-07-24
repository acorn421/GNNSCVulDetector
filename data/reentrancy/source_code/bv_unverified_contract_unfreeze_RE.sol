/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `msg.sender.call(abi.encodeWithSignature("onUnfreeze(uint256)", _value))` before the state updates
 * 2. The call checks if the caller is a contract (`msg.sender.code.length > 0`) and attempts to call an `onUnfreeze` function
 * 3. This external call happens BEFORE the critical state variables `freezeOf[msg.sender]` and `balanceOf[msg.sender]` are updated
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * This vulnerability requires multiple transactions and accumulated state to exploit:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract and freezes legitimate tokens (e.g., 1000 tokens)
 * - Contract state: `freezeOf[attacker] = 1000`, `balanceOf[attacker] = 0`
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Attacker calls `unfreeze(500)` from their malicious contract
 * - The assertion `assert(freezeOf[msg.sender] >= _value)` passes (1000 >= 500)
 * - The external call `msg.sender.call(...)` is made BEFORE state updates
 * - In the `onUnfreeze` callback, the attacker can call `unfreeze(500)` again
 * - The second call still sees the original state: `freezeOf[attacker] = 1000`
 * - Both calls succeed, but the attacker unfreezes 1000 tokens total while only having 1000 frozen
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Each subsequent transaction can build on the manipulated state from previous transactions
 * - The attacker can continue to exploit the inconsistent state across multiple calls
 * - The vulnerability compounds as the attacker can unfreeze more tokens than they actually had frozen
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * 1. **State Persistence:** The `freezeOf` and `balanceOf` mappings persist between transactions, allowing state manipulation to carry over
 * 2. **Accumulated Effect:** Each exploitation attempt builds on the previous state changes
 * 3. **Reentrancy Window:** The external call creates a window where the contract state is inconsistent, allowing multiple exploitations before the state is properly updated
 * 4. **Cross-Transaction State Dependency:** The vulnerability relies on the accumulated frozen balance from previous legitimate freeze operations
 * 
 * This creates a realistic vulnerability where an attacker can drain frozen tokens beyond their legitimate allocation through carefully orchestrated multi-transaction reentrancy attacks.
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
    // Assembly function to get code size of an address (Solidity 0.4.x)
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
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
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); 
        emit Freeze(msg.sender, _value);
        return true;
    }
    function unfreeze(uint256 _value) public returns (bool success) {
        assert(freezeOf[msg.sender] >= _value);
        assert(_value > 0); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call before state updates - vulnerability injection point
        if (extcodesize(msg.sender) > 0) {
            // Call to potentially malicious contract before state changes
            (bool callSuccess,) = msg.sender.call(abi.encodeWithSignature("onUnfreeze(uint256)", _value));
            // Continue execution even if call fails to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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