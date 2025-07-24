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
 * **Changes Made:**
 * 1. Added a callback to `IBurnCallback(burnNotifier).onBurn(msg.sender, _value)` before state modifications
 * 2. The callback occurs after the balance check but before the actual balance and totalSupply updates
 * 3. This violates the Checks-Effects-Interactions pattern by placing external calls before state changes
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `setBurnNotifier()` to register a malicious callback contract
 * 2. **Transaction 2**: Attacker calls `burn()` with their available balance
 * 3. **During Transaction 2**: The callback is triggered, allowing the malicious contract to:
 *    - Call `burn()` again (reentrancy) before the original state changes are committed
 *    - The balance check still passes because balances haven't been updated yet
 *    - This can be repeated multiple times within the same transaction
 * 4. **State Accumulation**: Each reentrant call reduces the same balance multiple times, allowing burning more tokens than owned
 * 
 * **Why Multiple Transactions Are Required:**
 * - Transaction 1 is needed to set up the malicious callback contract address
 * - Transaction 2 triggers the actual exploit through the callback mechanism
 * - The vulnerability relies on the persistent state of the `burnNotifier` address set in the previous transaction
 * - Without the prior registration of the callback contract, the reentrancy attack vector doesn't exist
 * 
 * **Realistic Context:**
 * - Burn notifications are common in DeFi protocols for integration purposes
 * - The callback mechanism appears legitimate for notifying external contracts about burn events
 * - The vulnerability is subtle and could easily be missed in code reviews
 * 
 * Note: This assumes the contract has been extended with a `burnNotifier` state variable and `setBurnNotifier()` function, which would be typical for contracts implementing callback mechanisms.
 */
pragma solidity ^0.4.25;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnCallback {
    function onBurn(address from, uint256 value) external;
}

contract CarbCorpToken {
    string public version = '0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    address public owner;
    uint256 public _totalSupply;

    // Added burnNotifier variable as required in burn
    address public burnNotifier;

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
        // Add burn notification callback before state updates
        if (burnNotifier != address(0)) {
            IBurnCallback(burnNotifier).onBurn(msg.sender, _value);
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