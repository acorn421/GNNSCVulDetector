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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external callback functionality before state updates. The vulnerability requires:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements burnCallback
 * 2. **Transaction 2**: Attacker calls burn() which triggers the callback before state updates
 * 3. **Reentrant calls**: The callback reenters burn() multiple times before original state updates complete
 * 
 * **Specific Changes Made:**
 * - Added contract detection using `msg.sender.code.length > 0`
 * - Inserted external call to `burnCallback(uint256)` before state modifications
 * - Added fallback call to `onBurn(uint256)` if first callback fails
 * - Moved state updates (balance and total supply reduction) after external calls
 * 
 * **Why Multi-Transaction Required:**
 * - Transaction 1 is needed to deploy the malicious contract with callback implementation
 * - Transaction 2 initiates the burn that triggers the vulnerable callback sequence
 * - The vulnerability depends on the persistent contract state (deployed callback contract)
 * - Multiple reentrant calls within Transaction 2 can drain more tokens than the attacker's balance
 * 
 * **Exploitation Flow:**
 * 1. Deploy malicious contract with burnCallback that reenters burn()
 * 2. Call burn() from malicious contract
 * 3. Callback is triggered before state updates
 * 4. Reentrant burn() calls succeed because balance hasn't been updated yet
 * 5. Each reentrant call passes the balance check but state updates are delayed
 * 6. Attacker can burn more tokens than they actually own
 * 
 * This creates a realistic vulnerability where the external callback mechanism (common in DeFi protocols) enables reentrancy exploitation through accumulated state manipulation across multiple function calls.
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

    function totalSupply() constant returns (uint256) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Low-level code check for contract:
        uint size;
        assembly { size := extcodesize(caller) }
        if (size > 0) {
            // Make external call before state updates (vulnerable pattern)
            bool callSuccess = msg.sender.call(bytes4(keccak256("burnCallback(uint256)")), _value);

            // Continue with burn even if callback fails
            if (!callSuccess) {
                // Fallback: attempt simpler notification
                msg.sender.call(bytes4(keccak256("onBurn(uint256)")), _value);
            }
        }
        // State updates happen after external calls (vulnerable)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        _totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balances[_from] < _value) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        balances[_from] -= _value;
        _totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
