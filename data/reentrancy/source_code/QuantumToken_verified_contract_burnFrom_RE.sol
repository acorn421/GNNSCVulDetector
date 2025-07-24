/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that notifies the _from address about burns before state updates. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **External Call Before State Changes**: The function calls _from.call() before updating balances and _totalSupply
 * 2. **State Persistence**: The vulnerability depends on persistent state across transactions - balances and allowances remain in inconsistent states
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker deploys a malicious contract and gets approval/tokens
 *    - Transaction 2: Attacker calls burnFrom, which triggers the callback
 *    - During callback: Malicious contract reenters burnFrom before state updates complete
 *    - Transaction 3+: Attacker can repeat the process, exploiting accumulated state inconsistencies
 * 
 * 4. **Realistic Integration**: The callback appears to be a legitimate feature for notifying contracts about burns, making it a realistic vulnerability that could appear in production code
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial setup (getting tokens/approval) happens in separate transactions
 * - The reentrancy attack itself may span multiple calls
 * - State corruption accumulates across transaction boundaries
 * - The attacker needs to set up the malicious contract beforehand
 * 
 * This creates a vulnerability where an attacker can burn tokens multiple times while only having their balance/allowance decremented once, leading to token supply manipulation and potential economic exploits.
 */
pragma solidity ^0.4.8;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract QuantumToken {
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

    function QuantumToken() {
        balances[msg.sender] = 24736207038308271;
        _totalSupply = 24736207038308271;
        name = 'Quantum';
        symbol = 'QAU';
        decimals = 8;
        owner = msg.sender;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowances[_owner][_spender];
    }

    function totalSupply() constant returns (uint256 totalSupply) {
        return _totalSupply;
    }

    function transfer(address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) return false;
        if (balances[msg.sender] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowances[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
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

    function burn(uint256 _value) returns (bool success) {
        if (balances[msg.sender] < _value) return false;
        balances[msg.sender] -= _value;
        _totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balances[_from] < _value) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if _from is a contract that might want to handle burn notifications
        uint256 codeSize;
        assembly { codeSize := extcodesize(_from) }
        
        // If _from is a contract, notify it about the burn before state changes
        if (codeSize > 0) {
            // Call notifyBurn function on the contract being burned from
            bool callSuccess = _from.call(bytes4(keccak256("notifyBurn(address,uint256)")), msg.sender, _value);
            // Continue regardless of call success for backward compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        _totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}