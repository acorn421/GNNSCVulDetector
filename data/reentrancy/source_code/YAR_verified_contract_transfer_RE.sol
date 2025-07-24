/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation Phase**: Attacker deploys a malicious contract that accumulates state across multiple legitimate transfer calls, building up a balance that can be used for the attack.
 * 
 * 2. **Reentrancy Setup**: The malicious contract implements `onTokenReceived` to reenter the transfer function when it receives tokens, but the reentrancy is designed to work with accumulated state from previous transactions.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker receives tokens legitimately, building balance
 *    - Transaction 2: Attacker initiates transfer to their malicious contract
 *    - During the callback, the malicious contract uses its accumulated balance to initiate new transfers
 *    - The state updates have already occurred, allowing the attacker to manipulate the contract state based on their accumulated position
 * 
 * The vulnerability is stateful because it depends on the attacker's accumulated balance from previous transactions, and multi-transaction because the exploit requires building up state over multiple calls before the final reentrancy attack can be executed effectively.
 */
pragma solidity ^0.4.16;

contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public;
}

contract EC20{
    uint256 public totalSupply;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient for notification - potential reentrancy point
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            TokenReceiver(_to).onTokenReceived(msg.sender, _value);
        }
        Transfer(msg.sender, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract YAR is EC20 {

    string public name;
    uint8 public decimals;
    string public symbol;
    constructor(uint256 _initialAmount, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {
        totalSupply = _initialAmount * 10 ** uint256(_decimalUnits);
        balances[msg.sender] = totalSupply;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
