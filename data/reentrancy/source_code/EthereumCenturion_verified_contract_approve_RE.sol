/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract before finalizing the approval state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to spender contract using `_spender.call(sig, msg.sender, _value)` before state update
 * 2. Included check for contract existence with `_spender.code.length > 0`
 * 3. Used `onApproval(address,uint256)` callback pattern which is realistic for token contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1:** User calls `approve(maliciousContract, 1000)` - malicious contract receives callback and can store state about pending approvals
 * - **Transaction 2:** Malicious contract uses accumulated information from previous approvals to call `transferFrom()` while simultaneously triggering new `approve()` calls
 * - **Transaction 3:** Further exploitation using state inconsistencies created across multiple approval transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation:** The malicious contract needs to accumulate information about multiple approval attempts across transactions
 * 2. **Timing Dependencies:** The exploit depends on the sequence of approval callbacks and subsequent token transfers happening across different transactions
 * 3. **Persistent State Manipulation:** The vulnerability leverages persistent storage state (`allowed` mapping) that changes between transactions
 * 4. **Race Conditions:** The exploit creates race conditions between approval notifications and actual approval finalization that unfold over multiple transactions
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by making external calls before state updates, creating a window for multi-transaction reentrancy attacks that depend on accumulated state changes.
 */
pragma solidity ^0.4.15;

library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract EthereumCenturion {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    function EthereumCenturion() public {
        totalSupply = 24000000;
        symbol = 'ETHC';
        owner = 0x5D4B79ef3a7f562D3e764a5e4A356b69c04cbC5A;
        balances[owner] = totalSupply;
        decimals = 0;
    }

    function balanceOf(address _owner) constant returns(uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns(uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) returns(bool) {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool) {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify spender before state finalization - creates reentrancy window
        if (isContract(_spender)) {
            bytes4 sig = bytes4(keccak256("onApproval(address,uint256)"));
            _spender.call(sig, msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function isContract(address _addr) internal constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function() {
        revert();
    }
}
