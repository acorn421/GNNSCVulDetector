/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE updating balances. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added contract detection using `_to.code.length > 0`
 * 2. Introduced external call to recipient contract using low-level `call()` with `onTokenReceived` signature
 * 3. Placed external call BEFORE balance updates, violating the Checks-Effects-Interactions pattern
 * 4. Continued execution regardless of call success to maintain normal functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to their malicious contract address
 * 2. **During callback**: Malicious contract's `onTokenReceived` function calls `transfer()` again (reentrancy)
 * 3. **State inconsistency**: First call hasn't updated balances yet, so second call sees old balance values
 * 4. **Transaction 2+**: Attacker repeats the process, progressively draining funds through accumulated state manipulation
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - Each individual `transfer()` call appears legitimate and passes balance checks
 * - The vulnerability emerges from the cumulative effect of multiple reentrant calls
 * - State changes persist between transactions, allowing progressive exploitation
 * - The attack requires building up inconsistent state through repeated calls
 * - Single-transaction exploitation is limited by gas costs and recursion depth
 * 
 * **Realistic Implementation:**
 * - The callback mechanism mimics real-world token standards (ERC-777 style)
 * - Contract detection is a common pattern in modern smart contracts  
 * - The vulnerability appears as a legitimate feature enhancement
 * - Maintains full backward compatibility with existing functionality
 * 
 * This creates a genuine security vulnerability that requires multiple transactions to exploit effectively while preserving the function's intended behavior.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if recipient is a contract and notify before balance update
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call BEFORE state update - creates reentrancy vulnerability
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of call success to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public  {
        revert();
    }
}
