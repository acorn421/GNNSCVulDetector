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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after updating balances but before updating allowances. This creates a state inconsistency window where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom, balances are updated, external call is made to malicious recipient contract
 * 2. **Malicious Contract**: During the external call, the recipient contract can call back into transferFrom or other functions while allowances haven't been updated yet
 * 3. **Transaction 2+**: The malicious contract can exploit the inconsistent state by making additional calls that rely on the stale allowance values
 * 
 * The vulnerability is stateful because:
 * - Balance updates persist between transactions
 * - Allowance updates are delayed until after the external call
 * - The malicious contract can accumulate tokens across multiple reentrancy calls
 * - Each call exploits the state inconsistency where balances reflect transfers but allowances don't
 * 
 * This requires multiple transactions because:
 * - The initial call must trigger the external call to the malicious recipient
 * - The malicious recipient must make subsequent calls during the same transaction
 * - The exploit depends on the accumulated state changes from the persistent balance updates
 * - A single atomic transaction alone cannot fully exploit this without the external call triggering additional state manipulations
 */
pragma solidity ^0.4.18;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract DynamicTradingRightsToken {
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

    function DynamicTradingRightsToken() public {
        balances[msg.sender] = 375000000000000000;
        _totalSupply = 375000000000000000;
        name = 'Dynamic Trading Rights';
        symbol = 'DTR';
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
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowances[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer (vulnerability injection point)
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // Update allowance after external call (vulnerability: state inconsistency window)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowances[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balances[msg.sender] < _value) return false;
        balances[msg.sender] -= _value;
        _totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balances[_from] < _value) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        balances[_from] -= _value;
        _totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
