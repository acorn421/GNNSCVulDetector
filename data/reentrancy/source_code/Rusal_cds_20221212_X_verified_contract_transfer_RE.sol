/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts AFTER state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Deploy malicious contract that implements onTokenReceived callback
 * **Transaction 2 (Initial Transfer)**: Transfer tokens to malicious contract, triggering the callback
 * **Transaction 3+ (Reentrant Calls)**: Malicious contract re-enters transfer function during callback, exploiting inconsistent state
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing external calls after state modifications. The malicious contract can:
 * 1. Receive tokens and get its balance updated
 * 2. During the callback, call transfer again before the original call completes
 * 3. Exploit the fact that balance checks pass but state is inconsistent
 * 4. Drain more tokens than originally intended through multiple reentrant calls
 * 
 * This requires multiple transactions because:
 * - First transaction sets up the attack contract
 * - Second transaction triggers the initial transfer and callback
 * - Subsequent reentrant calls within the callback exploit the vulnerability
 * - The attack builds up state across multiple function calls within the transaction sequence
 * 
 * The external call creates a window where the contract state is inconsistent, allowing sophisticated multi-call attacks that accumulate effects across the call stack.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract Rusal_cds_20221212_X is Ownable {

    string public constant name = " Rusal_cds_20221212_X        ";
    string public constant symbol = " RUSCX       ";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner public {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

            // Notify recipient contract about the transfer
            uint codeLength;
            assembly { codeLength := extcodesize(_to) }
            if(codeLength > 0) {
                bool notifySuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                if(!notifySuccess) {
                    // Revert the transfer if notification fails
                    balances[msg.sender] += _value;
                    balances[_to] -= _value;
                    return false;
                }
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
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

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
