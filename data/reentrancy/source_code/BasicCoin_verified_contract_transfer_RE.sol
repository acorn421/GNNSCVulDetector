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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before crediting their balance. The vulnerability creates a window where:
 * 
 * 1. **Transaction 1**: Sender's balance is deducted first, then external call is made to recipient
 * 2. **Transaction 2+**: During the external call, recipient can re-enter transfer() while sender's balance is already reduced but recipient's balance hasn't been credited yet
 * 3. **State Accumulation**: Each re-entrant call can drain more tokens from the sender since their balance check passes (balance was already reduced) but recipient keeps getting credited
 * 
 * The key stateful elements:
 * - Sender's balance is persistently modified before the external call
 * - Multiple re-entrant calls can exploit this intermediate state
 * - Each call accumulates more tokens to the attacking recipient
 * - The vulnerability requires multiple transaction calls to be effective since a single call would only transfer the intended amount
 * 
 * This pattern mimics real-world token notification systems where recipients need to be notified of incoming transfers, but creates a dangerous re-entrancy window that can be exploited across multiple calls.
 */
pragma solidity ^0.4.4;

contract BasicCoin{
	mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply = 0;
    string public name;                   
    uint8 public decimals;                
    string public symbol;   
	address public owner;
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    function safeMul(uint a, uint b) internal returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeSub(uint a, uint b) internal returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint a, uint b) internal returns (uint) {
        uint c = a + b;
        assert(c>=a && c>=b);
        return c;
    }

    function assert(bool assertion) internal {
        if (!assertion) throw;
    }
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Deduct from sender first
            balances[msg.sender] = safeSub(balances[msg.sender], _value);
            
            // External call to recipient before crediting their balance
            // This allows for transfer notifications and recipient processing
            if (_to.call(bytes4(bytes32(sha3("onTokenReceived(address,uint256)"))), msg.sender, _value)) {
                // Success case: credit recipient balance after successful callback
                balances[_to] = safeAdd(balances[_to], _value);
                Transfer(msg.sender, _to, _value);
                return true;
            } else {
                // Failure case: restore sender balance if callback fails
                balances[msg.sender] = safeAdd(balances[msg.sender], _value);
                return false;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        } else { return false; }
    }
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] = safeAdd(balances[_to], _value);
            balances[_from] = safeSub(balances[_from], _value);
            allowed[_from][msg.sender] = safeSub(allowed[_from][msg.sender], _value);
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }
    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
	function () payable {
        throw;
    }
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);if(!_spender.call(bytes4(bytes32(sha3("receiveApproval(address,uint256,address,bytes)"))), msg.sender, _value, this, _extraData)) { throw; }
        return true;
    }
	//token init
    function BasicCoin(
        uint256 initialSupply
    ) public {
        decimals = 18;   
        totalSupply = initialSupply * 10 ** uint256(decimals);  
        balances[msg.sender] = initialSupply * 10 ** uint256(decimals);  
        owner = msg.sender;
        name = "Basic Coin";
        symbol = "BASIC";
    }
}