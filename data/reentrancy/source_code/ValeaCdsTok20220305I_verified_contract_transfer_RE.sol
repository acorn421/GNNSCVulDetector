/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing the balance update. The vulnerability is stateful because:
 * 
 * 1. **State Persistence**: The sender's balance is decremented before the external call, creating an intermediate state where funds are "in transit" between transactions.
 * 
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker initiates transfer, external call triggers reentrancy where attacker's balance is already reduced
 *    - Transaction 2+: During reentrancy, attacker can call transfer again with remaining balance, creating a chain of nested calls
 *    - Each nested call sees the updated state from previous calls, allowing balance manipulation across the call stack
 * 
 * 3. **External Call Placement**: The external call happens after the sender's balance is decremented but before the recipient's balance is incremented, violating the Checks-Effects-Interactions pattern.
 * 
 * 4. **Realistic Implementation**: The onTokenReceived callback pattern is commonly used in real token contracts for notification purposes, making this vulnerability realistic and subtle.
 * 
 * The exploit works because each reentrancy level operates on the persistent state changes from previous levels, allowing an attacker to drain more funds than they should be able to transfer in a single transaction. The vulnerability cannot be exploited atomically - it requires the state changes to propagate through multiple nested function calls.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Deduct from sender first
            balances[msg.sender] -= _value;
            
            // External call to recipient (potential reentrancy point)
            // This allows the recipient to call back into this contract
            if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
                // If callback succeeds, complete the transfer
                balances[_to] += _value;
                Transfer(msg.sender, _to, _value);
                return true;
            } else {
                // If callback fails, revert the sender's balance change
                balances[msg.sender] += _value;
                return false;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
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