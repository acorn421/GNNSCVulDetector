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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address (_to) before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to be fully exploitable:
 *    - Transaction 1: An attacker deploys a malicious contract that implements onTokenReceived()
 *    - Transaction 2: The attacker calls approve() to set allowances for the malicious contract
 *    - Transaction 3: The attacker calls transferFrom() which triggers the external call to their malicious contract
 *    - Transaction 4+: The malicious contract's onTokenReceived() callback can re-enter transferFrom() or other functions
 * 
 * 2. **State Persistence**: The vulnerability relies on persistent state changes:
 *    - Allowances set in previous transactions remain available for exploitation
 *    - Balance checks pass but state isn't updated until after the external call
 *    - The malicious contract can accumulate state across multiple calls
 * 
 * 3. **Realistic Exploitation Scenario**:
 *    - The attacker's malicious contract can re-enter transferFrom() with the same parameters
 *    - Since state updates happen after the external call, the same allowance and balance checks pass multiple times
 *    - Each reentrant call can drain more tokens before the original state updates complete
 *    - The attacker can also call other functions like transfer() or approve() during the reentrancy
 * 
 * 4. **Why Multiple Transactions Are Required**:
 *    - The attacker must first deploy and set up the malicious contract (Transaction 1)
 *    - Allowances must be established through approve() calls (Transaction 2)
 *    - The actual exploit requires triggering transferFrom() (Transaction 3)
 *    - The reentrancy callback enables additional state manipulation (Transaction 4+)
 * 
 * This creates a realistic, production-like vulnerability where the external call to notify recipients of token transfers becomes an attack vector for multi-transaction reentrancy exploitation.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract ValeaCdsTok20220305I is Ownable {
    
    string public constant name = "ValeaCdsTok20220305I";
    
    string public constant symbol = "VALEAI";
    
    uint32 public constant decimals = 8;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }
    
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to recipient before state updates - enables reentrancy
            if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value)) {
                // Callback completed successfully
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
}