/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating balances. This violates the Checks-Effects-Interactions (CEI) pattern by placing the external call before state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker deploys malicious contract that implements onTokenReceived() callback
 * 2. **Transaction 2**: Victim calls transfer() to send tokens to malicious contract
 * 3. **During callback**: Malicious contract re-enters transfer() while original sender's balance hasn't been updated yet
 * 4. **Transaction 3+**: Repeated exploitation through coordinated reentrancy calls
 * 
 * The vulnerability is stateful because:
 * - It depends on the persistent balance state in the `balances` mapping
 * - Balance inconsistencies accumulate across multiple function calls
 * - The attack requires setting up the malicious contract in advance (separate transaction)
 * - Exploitation involves a sequence of coordinated calls that manipulate state over time
 * 
 * This creates a realistic window where an attacker can drain funds by repeatedly calling transfer() during the callback, before the original balance deduction takes effect.
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
    // Added storage variable declaration for balances
    mapping(address => uint256) internal balances;

    function balanceOf(address _owner)public view returns (uint256 balance);
    function transfer(address _to, uint256 _value)public returns (bool success){
        require(_to != address(0));
        require(_value <= balances[msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient of incoming transfer (external call before state update)
        if(isContract(_to)) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value)public returns (bool success);
    function approve(address _spender, uint256 _value)public returns (bool success);
    function allowance(address _owner, address _spender)public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
contract MaxWellToken is ERC20{
    using SafeMath for uint256;
    string public name   = "MaxWellToken";
    string public symbol = "MWT"; 
    uint8 public decimals=18;
    uint256 public totalSupply;
    // The balances mapping is now inherited from ERC20
    // mapping(address => uint256) balances; // removed duplicate
    mapping (address => mapping (address => uint256)) internal allowed;
    
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
