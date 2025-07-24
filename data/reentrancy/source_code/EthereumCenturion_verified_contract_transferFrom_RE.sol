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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Completion**: Added an external call to the recipient contract's `onTokenReceived` function after updating the recipient's balance but before updating the sender's balance and allowance.
 * 
 * 2. **Violation of Checks-Effects-Interactions**: The external call is made in the middle of state updates, creating a window where the contract state is inconsistent (recipient balance updated but sender balance and allowance not yet decremented).
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker sets up allowance for a malicious contract
 *    - **Transaction 2**: Legitimate user calls transferFrom to transfer tokens to the malicious contract
 *    - **During Transaction 2**: The malicious contract's onTokenReceived hook is called, which can then call transferFrom again with the same allowance (since it hasn't been decremented yet)
 *    - **Continued Exploitation**: The malicious contract can continue to call transferFrom multiple times using the same allowance value, draining funds
 * 
 * 4. **Stateful Nature**: The vulnerability exploits the persistent state of the `allowed` mapping across multiple function calls within the same transaction and across different transactions.
 * 
 * 5. **Realistic Implementation**: The recipient notification pattern is common in modern token standards (like ERC-777) and would not look suspicious in a code review.
 * 
 * **Exploitation Scenario**:
 * - The attacker creates a malicious contract with an `onTokenReceived` function
 * - When tokens are transferred to this contract, it re-enters the transferFrom function
 * - Since the allowance hasn't been updated yet, the malicious contract can transfer more tokens than originally intended
 * - This can be repeated multiple times within the same transaction, effectively allowing the attacker to drain the approved amount multiple times
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability that requires the accumulated state changes and external contract interaction to be exploitable.
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

    function balanceOf(address _owner) public constant returns(uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns(uint256 remaining) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balances[_to] = balances[_to].add(_value);
        
        // External call to notify recipient before all state updates complete
        if (isContract(_to)) {
            // Call recipient contract's onTokenReceived hook
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
        }
        
        // State updates happen after external call - vulnerability window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function() public {
        revert();
    }
}
