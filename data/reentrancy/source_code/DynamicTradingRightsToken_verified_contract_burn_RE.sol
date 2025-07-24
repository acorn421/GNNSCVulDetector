/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a callback to `IBurnCallback(burnCallback).onBurnComplete()` before state updates
 * 2. **Violated CEI Pattern**: The external call occurs before `balances[msg.sender] -= _value` and `_totalSupply -= _value`
 * 3. **Passed Current State**: The callback receives the current balance before it's updated
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker sets up malicious callback contract and registers it as `burnCallback`
 * 2. **Transaction 2 (Initial Burn)**: Attacker calls `burn(100)` with balance of 200
 *    - Function checks `balances[attacker] >= 100` ✓ (200 >= 100)
 *    - External call to `onBurnComplete(attacker, 100, 200)` is made
 *    - **REENTRANCY**: Callback calls `burn(100)` again in same transaction
 *    - Second call sees unchanged state: `balances[attacker] = 200` (not yet updated)
 *    - Second call passes validation and makes another callback
 *    - This creates a recursive chain allowing multiple burns before any state updates
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Persistence**: The vulnerability depends on the persistent state of `balances` and `burnCallback` across transactions
 * - **Callback Setup**: Attacker needs separate transaction to set up the malicious callback contract
 * - **Accumulated Effect**: Multiple reentrant calls accumulate to drain more tokens than the attacker actually owns
 * - **Cross-Transaction Impact**: The effects compound across transaction boundaries as the attacker can repeatedly exploit the same pattern
 * 
 * **Exploitation Requirements:**
 * - Requires at least 2 transactions (setup + exploitation)
 * - Depends on persistent contract state (`burnCallback` address and `balances` mapping)
 * - Cannot be exploited in a single atomic transaction without the callback mechanism being pre-established
 * - State changes persist between transactions, enabling repeated exploitation
 */
pragma solidity ^0.4.18;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnCallback {
    function onBurnComplete(address from, uint256 value, uint256 balance) external;
}

contract DynamicTradingRightsToken {
    string public version = '0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    address public owner;
    uint256 public _totalSupply;
    address public burnCallback; // Declared burnCallback

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
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
        allowances[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balances[msg.sender] < _value) return false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to burn callback before state updates
        // This allows for stateful reentrancy across multiple transactions
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onBurnComplete(msg.sender, _value, balances[msg.sender]);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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