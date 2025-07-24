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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract before updating the approval state. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **Transaction 1**: Initial setup where malicious spender uses approve() to set initial allowance, but during the external call notification, it can re-enter and exploit the fact that the allowance hasn't been updated yet.
 * 
 * 2. **Transaction 2+**: The malicious spender can call approve() again, and during the onApproval callback, it can:
 *    - Read the old allowance value (still not updated)
 *    - Call transferFrom() to spend tokens based on previous allowance
 *    - Manipulate the approval process by setting different allowances
 *    - Build up accumulated state corruption across multiple transactions
 * 
 * The vulnerability is stateful because:
 * - The `allowed` mapping persists between transactions
 * - Each transaction can build upon the corrupted state from previous transactions
 * - The external call happens before state updates, allowing reentrancy to read stale state
 * - Multiple approve() calls can create cascading effects where each call's reentrancy affects subsequent calls
 * 
 * This creates a realistic vulnerability where a malicious contract can exploit the notification mechanism to manipulate allowances across multiple transactions, potentially draining funds or corrupting approval states in ways that accumulate over time.
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

// Interface for external contract call in approve()
interface IApprovalNotifier {
    function onApproval(address approver, uint256 value) external;
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

    function PREZCoin () public {
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
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        var _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify spender about approval if it's a contract
        if (isContract(_spender)) {
            IApprovalNotifier(_spender).onApproval(msg.sender, _value);
        }
        
        // Update state after external call (vulnerability injection)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public  {
        revert();
    }
    
    // Helper function to detect if _addr is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
