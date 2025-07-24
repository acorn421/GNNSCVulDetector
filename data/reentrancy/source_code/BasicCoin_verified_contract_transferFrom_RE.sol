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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address (_to) before updating the allowance mapping. This creates a classic reentrancy attack vector where:
 * 
 * 1. **First Transaction**: Initial transferFrom call performs balance updates but makes external call to recipient before updating allowance
 * 2. **Reentrancy Window**: During the external call, the recipient contract can call back into transferFrom
 * 3. **State Persistence**: The allowance remains unchanged during the external call, allowing the same approval to be used multiple times
 * 4. **Multi-Transaction Exploitation**: Requires multiple transactions because:
 *    - Transaction 1: Initial transfer with external call triggers recipient
 *    - Transaction 2+: Recipient contract re-enters transferFrom with same allowance
 *    - Each re-entry can transfer tokens until allowance is finally updated
 * 
 * The vulnerability exploits the fact that balance updates occur before allowance updates, and the external call creates a window where the original allowance can be reused across multiple transactions. This is a realistic pattern seen in production code where developers add recipient notifications without considering reentrancy implications.
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
            balances[msg.sender] = safeSub(balances[msg.sender], _value);
            balances[_to] = safeAdd(balances[_to],_value);
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] = safeAdd(balances[_to], _value);
            balances[_from] = safeSub(balances[_from], _value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient of incoming transfer before updating allowance
            if (_to.call(bytes4(bytes32(sha3("onTokenReceived(address,address,uint256)"))), _from, msg.sender, _value)) {
                // External call completed successfully
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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