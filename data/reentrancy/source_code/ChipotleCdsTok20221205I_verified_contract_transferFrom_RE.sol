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
 * Added an external call to the recipient address (_to) after the validity checks but before state updates. This creates a stateful, multi-transaction reentrancy vulnerability where:
 * 
 * 1. **Stateful Nature**: The function relies on persistent state variables (allowed mapping and balances mapping) that carry over between transactions.
 * 
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker sets up allowances using approve() function
 *    - Transaction 2: Attacker calls transferFrom() which triggers the external call
 *    - Within the external call callback, the attacker can recursively call transferFrom() again while the original state (allowances and balances) hasn't been updated yet
 * 
 * 3. **Exploitation Scenario**: 
 *    - Attacker creates a malicious contract as the recipient (_to)
 *    - The malicious contract implements onTokenReceived() to re-enter transferFrom()
 *    - Since allowed[_from][msg.sender] and balances[_from] haven't been decremented yet, the attacker can drain more tokens than authorized
 *    - Each recursive call can transfer the full allowance amount again
 * 
 * 4. **Why Multiple Transactions Are Required**: The vulnerability cannot be exploited in a single transaction because:
 *    - The attacker must first establish allowances in a separate transaction
 *    - The exploitation requires the recipient contract to be deployed and configured
 *    - The recursive calls create a sequence of state-dependent operations across multiple call frames
 * 
 * This creates a realistic vulnerability pattern where external calls occur before state updates, violating the checks-effects-interactions pattern and enabling multi-transaction reentrancy attacks.
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

contract ChipotleCdsTok20221205I is Ownable {
    
    string public constant name = "ChipotleCdsTok20221205I";
    
    string public constant symbol = "CHIPOTI";
    
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
            
            // External call to notify recipient before state updates
            // This creates a reentrancy window where state is still unchanged
            if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                // Continue with transfer
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