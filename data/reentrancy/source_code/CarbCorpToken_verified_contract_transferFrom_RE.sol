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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification hook that creates a vulnerable state window. The function now updates balances before making an external call to the recipient contract, but only decrements the allowance after the external call completes. This creates a multi-transaction exploitation scenario where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom() with a malicious contract as _to. Balances are updated, but when the external call is made, the malicious contract can reenter and call transferFrom() again since the allowance hasn't been decremented yet.
 * 
 * 2. **Transaction 2+**: The malicious contract can make additional calls to transferFrom() within the same transaction or across multiple transactions, exploiting the fact that the allowance reduction happens after the external call.
 * 
 * The vulnerability is stateful because:
 * - Balance updates persist between calls
 * - Allowance state remains unchanged during the vulnerable window
 * - The exploit requires building up state across multiple function invocations
 * - The victim's balances are progressively drained across multiple transfers
 * 
 * This represents a realistic scenario where a "feature" (transfer notifications) introduces a critical vulnerability through improper state management ordering.
 */
pragma solidity ^0.4.25;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract CarbCorpToken {
    string public version = '0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    address public owner;
    uint256 public _totalSupply;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        balances[msg.sender] = 10000000000;
        _totalSupply = 10000000000;
        name = 'CarbShare';
        symbol = 'eCARB';
        decimals = 8;
        owner = msg.sender;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowances[_owner][_spender];
    }

    function totalSupply() public constant returns (uint256 supply) {
        return _totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) return false;
        if (balances[msg.sender] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowances[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) return false;
        if (balances[_from] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update balances first (vulnerable state)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about incoming transfer - VULNERABLE EXTERNAL CALL
        if (isContract(_to)) {
            bool _callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            if (!_callSuccess) {
                // If notification fails, revert the transfer
                balances[_from] += _value;
                balances[_to] -= _value;
                return false;
            }
        }
        // Update allowance after external call (vulnerable ordering)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowances[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper function for contract detection in Solidity <0.5.0
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balances[msg.sender] < _value) return false;
        balances[msg.sender] -= _value;
        _totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balances[_from] < _value) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        balances[_from] -= _value;
        _totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
}
