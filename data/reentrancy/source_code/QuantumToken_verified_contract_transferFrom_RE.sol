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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a callback mechanism that notifies the recipient contract about incoming tokens using `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)`
 * 2. **Reordered State Updates**: Moved the allowance deduction (`allowances[_from][msg.sender] -= _value`) to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. **Preserved Function Logic**: All original functionality remains intact - the function still performs token transfers correctly under normal conditions
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1 (Setup)**: Victim approves attacker contract for 100 tokens via `approve(attackerContract, 100)`
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls `transferFrom(victim, attackerContract, 100)`
 *    - Balance updates occur (victim loses 100, attacker gains 100)
 *    - External call to `attackerContract.onTokenReceived()` is made
 *    - **REENTRANCY POINT**: Attacker's contract calls `transferFrom(victim, attackerContract, 100)` again
 *    - Second call succeeds because allowance hasn't been decremented yet
 *    - Attacker gains another 100 tokens
 *    - Original call completes, allowance is decremented by 100
 * 3. **Result**: Attacker received 200 tokens but only 100 was deducted from allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Persistence**: The allowance state persists between transactions and is only decremented after the external call
 * - **Attack Setup**: Requires initial approval transaction to establish the allowance
 * - **Reentrancy Window**: The vulnerability only exists during the external call window, which can be exploited by the recipient contract making additional calls
 * - **Accumulated State**: The attack relies on the allowance state being checked at the beginning but only updated at the end, creating a window for multiple transfers
 * 
 * **Technical Vulnerability Details:**
 * - **Root Cause**: Violation of Checks-Effects-Interactions pattern
 * - **Attack Vector**: Malicious recipient contracts can reenter during the callback
 * - **State Dependency**: Requires persistent allowance state from previous approval transactions
 * - **Impact**: Double-spending attacks where tokens can be transferred multiple times against a single allowance
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to both set up and exploit, making it a perfect example of multi-transaction reentrancy attacks in token contracts.
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

    function QuantumToken() public {
        balances[msg.sender] = 24736207038308271;
        _totalSupply = 24736207038308271;
        name = 'Quantum';
        symbol = 'QAU';
        decimals = 8;
        owner = msg.sender;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowances[_owner][_spender];
    }

    function totalSupply() public constant returns (uint256) {
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
        // Notify recipient about incoming transfer - VULNERABLE EXTERNAL CALL
        if (isContract(_to)) {
            if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)) {
                // Callback succeeded
            }
        }
        // State update happens AFTER external call - VULNERABILITY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowances[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
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

    // --- Internal Helper for contract detection (because address.code not available in 0.4.x) ---
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
