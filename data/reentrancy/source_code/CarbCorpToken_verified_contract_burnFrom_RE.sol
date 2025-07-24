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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a call to `tokenRecipient(_from).receiveApproval()` before updating balances and allowances
 * 2. **Violated CEI Pattern**: The external call occurs before critical state modifications (balances, _totalSupply, allowances)
 * 3. **Added Allowance Deduction**: Explicitly added `allowances[_from][msg.sender] -= _value` to create more state inconsistency opportunities
 * 4. **Conditional External Call**: Only triggers when `_from != msg.sender`, making it realistic for delegated burns
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract implements `receiveApproval` function
 * - Attacker gets allowance to burn tokens from victim's account
 * - Attacker calls `burnFrom(victim, amount)` 
 * 
 * **Transaction 2 (Reentrancy Exploitation):**
 * - During the external call in Transaction 1, attacker's `receiveApproval` function is triggered
 * - At this point, victim's balance and allowance are still unchanged (state inconsistency)
 * - Attacker can reenter and call `burnFrom` again or manipulate other functions
 * - The state inconsistency allows multiple operations before the original state updates complete
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability exploits the window between external call and state updates
 * 2. **Allowance Persistence**: The allowance system requires multiple interactions to fully exploit
 * 3. **Realistic Attack Vector**: Real attackers would need to set up allowances in separate transactions first
 * 4. **State Inconsistency Window**: The vulnerability creates a window where balances, allowances, and totalSupply are temporarily inconsistent across transaction boundaries
 * 
 * **Exploitation Impact:**
 * - Attacker can burn more tokens than they should be allowed to
 * - Double-spending of allowances becomes possible
 * - Total supply calculations can become inconsistent
 * - Multiple burns can occur before state updates, leading to arithmetic underflows or overflows
 * 
 * This creates a realistic, stateful vulnerability that requires careful transaction sequencing to exploit, making it an excellent example for security research and testing.
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

    function CarbCorpToken() public {
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
        balances[msg.sender] -= _value;
        _totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balances[_from] < _value) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify burn event before state updates (vulnerability injection)
        if (_from != msg.sender) {
            // Call external contract to handle burn notification
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        _totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowances[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}