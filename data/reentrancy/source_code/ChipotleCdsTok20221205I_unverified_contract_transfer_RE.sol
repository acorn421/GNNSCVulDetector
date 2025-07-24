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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that notifies recipient contracts before state updates. This creates a time window where the recipient can re-enter the transfer function while the original sender's balance hasn't been decremented yet, but the balance checks have already passed.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))`
 * 2. Placed this call BEFORE the state updates (`balances[msg.sender] -= _value`)
 * 3. Added contract existence check (`_to.code.length > 0`) to only call contracts
 * 4. Added require statement to ensure callback success
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** Attacker deploys a malicious contract that implements `onTokenReceived` callback. This contract can receive tokens and has logic to re-enter the transfer function.
 * 
 * **Transaction 2 (Initial Transfer):** Legitimate user transfers tokens to the malicious contract:
 * - Balance check passes (sender has sufficient balance)
 * - External call to malicious contract's `onTokenReceived` is made
 * - Malicious contract's callback is triggered BEFORE sender's balance is decremented
 * - At this point, sender's balance is still unchanged, creating inconsistent state
 * 
 * **Transaction 3 (Exploitation):** The malicious contract's callback immediately calls `transfer` again:
 * - The original sender's balance hasn't been decremented yet
 * - Balance checks pass again (using stale balance state)
 * - Multiple transfers can be executed using the same balance
 * - State accumulates across these nested calls
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence:** The vulnerability depends on the persistent balance state in the `balances` mapping that exists between transactions
 * 2. **Callback Setup:** The malicious contract must be deployed and configured in a separate transaction
 * 3. **Accumulated Effect:** Each successful re-entrant call further depletes the victim's balance while the original balance check remains valid
 * 4. **Race Condition:** The vulnerability exploits the time window between balance verification and state updates across multiple function calls
 * 
 * This creates a realistic scenario where an attacker can drain more tokens than they should be able to by leveraging the callback mechanism across multiple nested calls.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    constructor() public {
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract about incoming transfer before state update
            uint codeLength;
            assembly { codeLength := extcodesize(_to) }
            if(codeLength > 0) {
                bool callSuccess;
                bytes memory data = abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value);
                assembly {
                    let ptr := add(data, 32)
                    callSuccess := call(gas, _to, 0, ptr, mload(data), 0, 0)
                }
                require(callSuccess, "Transfer notification failed");
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
