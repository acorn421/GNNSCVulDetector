/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code existence using `_to.code.length > 0`
 * 2. Introduced an external call to `_to.call()` with `onTokensMinted(uint256)` signature
 * 3. Positioned the external call BEFORE the critical state updates (`balances[_to]` and `totalSupply`)
 * 4. The call happens within the same transaction but creates a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokensMinted(uint256)`
 * 2. **Transaction 2**: Owner calls `mint(attackerContract, amount1)` - This triggers the callback where the attacker's contract can:
 *    - Call `mint()` again recursively before the first call's state updates complete
 *    - The recursive call passes the initial assert checks because state hasn't been updated yet
 *    - Multiple mint operations can be stacked in the call stack
 * 3. **State Accumulation**: Each recursive call adds to the same `balances[_to]` and `totalSupply` when the call stack unwinds
 * 4. **Result**: The attacker receives tokens worth `amount1 * number_of_recursive_calls`
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy a malicious contract (Transaction 1)
 * - The actual exploitation happens when the owner legitimately calls mint (Transaction 2)
 * - The vulnerability exploits the state inconsistency window created by the external call
 * - The malicious contract's callback can trigger additional minting operations before the original state updates complete
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on the persistent state of `balances` and `totalSupply`
 * - The attacker's contract must be deployed and have the callback function implemented
 * - Each recursive call builds upon the previous state, creating cumulative effects
 * - The exploit requires the accumulated state changes from multiple nested calls within the transaction
 * 
 * This creates a realistic reentrancy vulnerability that appears as a legitimate feature (mint notifications) but allows token inflation through recursive calls.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}

contract BFinanceTokI is Ownable {

    string public constant name = "\tBFinanceTokI\t\t";
    string public constant symbol = "\tBFTI\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);

        /*
            Solidity 0.4.x does not support address.code.length. Equivalent check for contract code:
            Using extcodesize(_to):
        */
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // External call before state update creates reentrancy window
            bool success = _to.call(bytes4(keccak256("onTokensMinted(uint256)")), _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }

    function approve(address _spender, uint _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
