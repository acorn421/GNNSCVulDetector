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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between balance updates and allowance updates. This violates the Checks-Effects-Interactions pattern and creates a window for reentrancy attacks.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))` 
 * 2. Positioned this call AFTER balance updates but BEFORE allowance updates
 * 3. Added a check `if(_to.code.length > 0)` to only call contracts (realistic enhancement)
 * 4. The external call appears as a legitimate token notification feature
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker gets approval for 1000 tokens: `approve(attacker, 1000)`
 * - Attacker deploys malicious contract with `onTokenReceived` callback
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Call `transferFrom(victim, maliciousContract, 500)`
 * - Balances are updated: victim -500, maliciousContract +500
 * - External call triggers `maliciousContract.onTokenReceived()`
 * - Inside callback: allowance is still 1000 (not yet decremented!)
 * - Malicious contract calls `transferFrom(victim, attacker, 500)` again
 * - This succeeds because allowance check passes (still sees 1000)
 * - Balances updated again: victim -500, attacker +500
 * - Original call resumes, decrements allowance to 500
 * 
 * **Transaction 3+ (Repeated Exploitation):**
 * - Attacker can repeat this pattern, exploiting the time window between balance updates and allowance updates
 * - Each transaction can drain more tokens than the original allowance should permit
 * - The vulnerability accumulates across multiple transactions due to the persistent state inconsistency
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Dependency**: The vulnerability relies on the allowance state persisting between the external call and the allowance update
 * 2. **Reentrancy Window**: The attack requires the external call to trigger during the vulnerable state window
 * 3. **Accumulated Exploitation**: Multiple transactions allow the attacker to drain significantly more tokens than initially approved
 * 4. **Realistic Attack Pattern**: Real-world reentrancy attacks often require multiple coordinated transactions to maximize damage
 * 
 * The vulnerability is stateful because it depends on the allowance state remaining unchanged during the external call, and multi-transaction because the full exploitation requires multiple nested calls to maximize the token drainage.
 */
pragma solidity ^0.4.24;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {return 0;}
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
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
contract ERC20{
    // State variables
    mapping(address => uint256) internal balances;
    mapping (address => mapping (address => uint256)) internal allowed;
    
    function balanceOf(address _owner)public view returns (uint256 balance);
    function transfer(address _to, uint256 _value)public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value)public returns (bool success) {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);

        // Use SafeMath functions via fully qualified call
        balances[_from] = SafeMath.sub(balances[_from], _value);
        balances[_to] = SafeMath.add(balances[_to], _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming tokens - VULNERABILITY: External call before allowance update
        if(_to.code.length > 0) {
            (bool innerSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = SafeMath.sub(allowed[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }
    function approve(address _spender, uint256 _value)public returns (bool success);
    function allowance(address _owner, address _spender)public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
contract MaxWellToken is ERC20{
    using SafeMath for uint256;
    string public name   = "MaxWellToken";
    string public symbol = "MWT"; 
    uint8 public decimals=18;
    uint256 public totalSupply;
    // mapping(address => uint256) balances;
    // mapping (address => mapping (address => uint256)) internal allowed;
    // Already declared in ERC20 interface, so do not redeclare
    
    constructor(uint256 initialSupply)public{
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply;
    }
    
    function balanceOf(address _owner)public view returns (uint256 balance){
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value)public returns (bool success){
        require(_to != address(0));
        require(_value <= balances[msg.sender]);
        
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
     
    function transferFrom(address _from, address _to, uint256 _value)public returns (bool success){
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
    
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value)public returns (bool success){
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true; 
    }
    
    function allowance(address _owner, address _spender)public view returns (uint256 remaining){
        return allowed[_owner][_spender];
    }
}
