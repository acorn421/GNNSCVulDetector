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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates but before allowance updates. This creates a critical window where malicious contracts can exploit state inconsistencies across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added contract existence check: `if (_to.code.length > 0)` to identify contract recipients
 * 2. Introduced external call: `_to.call(selector, _from, msg.sender, _value)` that invokes `onTokenReceived` callback
 * 3. Positioned the external call AFTER balance updates but BEFORE allowance update, violating the Checks-Effects-Interactions pattern
 * 4. Used low-level `.call()` which doesn't revert on failure, making the vulnerability more subtle
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves malicious contract for large allowance (e.g., 1000 tokens)
 * - Normal approval transaction, no exploitation yet
 * 
 * **Transaction 2 (Initial Attack):**
 * - Legitimate user calls `transferFrom` with malicious contract as `_to`
 * - Balances are updated: `balances[_to] += _value`, `balances[_from] -= _value`
 * - External call triggers malicious contract's `onTokenReceived` function
 * - Malicious contract can now call `transferFrom` again with same allowance
 * 
 * **Transaction 3 (Reentrant Exploitation):**
 * - During the external call in Transaction 2, malicious contract calls `transferFrom` again
 * - Since allowance hasn't been updated yet, the same allowance can be used multiple times
 * - This creates a state where tokens are transferred but allowance isn't properly decremented
 * - The attack can drain more tokens than the original allowance permitted
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * 1. **State Accumulation**: The vulnerability relies on allowance state persisting between transactions
 * 2. **Timing Window**: The external call creates a window where state is inconsistent across multiple function calls
 * 3. **Cross-Transaction Impact**: The incomplete state update in one transaction enables exploitation in subsequent calls
 * 4. **Persistent State Corruption**: The allowance manipulation effects persist beyond single transactions
 * 
 * **Exploitation Requirements:**
 * - Requires at least 2 transactions: one to set up allowance, another to exploit
 * - The reentrant call happens within the context of the second transaction but affects persistent state
 * - Cannot be exploited in a single isolated transaction without prior state setup
 */
pragma solidity ^0.4.19;
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract PREZCoin  {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    constructor() public {
        totalSupply = 10000000000000000000;
        symbol = 'PREZ';
        owner = 0xCe2588aB8C2fB15c8b60c5A251552a613f9c8FE9;
        balances[owner] = totalSupply;
        decimals = 9;
        }

    function balanceOf(address _owner) public view returns(uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public view returns(uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) public returns(bool) {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer notification hook - enables reentrancy
        if (isContract(_to)) {
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            _to.call(selector, _from, msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = _allowance.sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function() public  {
        revert();
    }
}
