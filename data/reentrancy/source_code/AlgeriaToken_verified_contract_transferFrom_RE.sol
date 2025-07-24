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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before the allowance state is updated. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added recipient notification mechanism using low-level call to `onTokenReceived` function
 * 2. Placed the external call AFTER balance updates but BEFORE allowance decrement
 * 3. This creates a vulnerable window where balances are updated but allowance remains unchanged
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Token owner calls `approve(attacker, 1000)` to grant allowance
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls `transferFrom(owner, maliciousContract, 500)`
 *    - Function updates balances: `balances[owner] -= 500`, `balances[maliciousContract] += 500`
 *    - External call triggers `maliciousContract.onTokenReceived()`
 *    - During callback: `allowed[owner][attacker]` still equals 1000 (not decremented yet)
 *    - Malicious contract calls `transferFrom(owner, attacker, 500)` again
 *    - Second call succeeds because allowance check passes (still 1000 >= 500)
 *    - Balances updated again, but allowance still not decremented in nested call
 * 3. **Transaction 3+ (Continued Drain)**: Pattern repeats until owner's balance is drained
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - Allowance must be set in a prior transaction via `approve()`
 * - Each successful `transferFrom` call depends on accumulated allowance state from previous transactions
 * - The vulnerability exploits the persistent state inconsistency between balance updates and allowance decrements across multiple calls
 * - Cannot be exploited in a single transaction without pre-existing allowance state
 * 
 * **Stateful Nature:**
 * - Exploits persistent allowance state that accumulates across transactions
 * - Requires specific state setup (allowance > 0) from previous transactions
 * - State changes (balance transfers) persist and compound across multiple exploitation attempts
 */
pragma solidity ^0.4.11;

interface IERC20  {
    function totalSupply() constant returns (uint256 totalSupply);
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract AlgeriaToken is IERC20 {
    uint public constant _totalSupply= 10000000000;
    string public constant symbol= "☺ DZT";
    string public constant name= "Algeria Token";
    uint8 public constant decimals = 3;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    function AlgeriaToken() public {
        balances[msg.sender] = _totalSupply;
    }
    
    function totalSupply() constant returns (uint256) {
        return _totalSupply;
    }
    
    function balanceOf(address _owner) constant returns (uint256) {
        return balances[_owner];
    }
    function transfer(address _to, uint256 _value) returns (bool) {
        require(
            balances[msg.sender] >= _value
            && _value > 0
            );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) returns (bool) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0
            );
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (isContract(_to)) {
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            _to.call(selector, _from, msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    function approve(address _spender, uint256 _value) returns (bool) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];   
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
