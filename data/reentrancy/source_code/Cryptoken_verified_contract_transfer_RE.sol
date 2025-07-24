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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract with improper state management. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` with `onTokenReceived` callback
 * 2. Implemented state rollback mechanism when callback fails
 * 3. Created race condition between balance updates and external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Victim calls `transfer()` to malicious contract
 * 3. **During Transaction 2**: Malicious contract's `onTokenReceived` is called, which can:
 *    - Call back to `transfer()` before original call completes
 *    - Manipulate balances while original transfer is still in progress
 *    - Cause state inconsistencies across multiple nested calls
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires setting up a malicious contract first (Transaction 1)
 * - The actual exploitation happens during subsequent transfers (Transaction 2+)
 * - The stateful nature means balances persist between transactions, allowing accumulated exploitation
 * - The attacker can repeatedly exploit by calling transfer multiple times with different amounts
 * 
 * **Exploitation Flow:**
 * 1. Deploy malicious contract with `onTokenReceived` that calls back to transfer
 * 2. Get tokens transferred to malicious contract
 * 3. During callback, re-enter transfer function to manipulate balances
 * 4. Repeat across multiple transactions to drain tokens
 * 
 * The vulnerability is stateful because balance changes persist between transactions, and multi-transaction because it requires contract deployment + exploitation sequence.
 */
//Cryptoken
//Ȼ

pragma solidity ^0.4.11;

contract Token {
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
contract StandardToken is Token {
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // INJECTED: Notify recipient contract before finalizing transfer
            uint256 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                if (!callSuccess) {
                    // VULNERABILITY: Revert state changes if callback fails
                    balances[msg.sender] += _value;
                    balances[_to] -= _value;
                    return false;
                }
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;
}
contract Cryptoken is StandardToken {

    function () {
        //if ether is sent to this address, send it back.
        revert();
    }

   


    string public name = "Cryptoken";      
    uint8 public decimals = 22;                
    string public symbol = "CTN";
    string public version = 'H1.0';    




    constructor(
        ) public {
        balances[msg.sender] = 500000000000000000000000000000000;               
        totalSupply = 500000000000000000000000000000000;                       
        name = "Cryptoken";                                  
        decimals = 22;                            
        symbol = "CTN";                               
    }

    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);

        
        if(!_spender.call(bytes4(keccak256("receiveApproval(address,uint256,address,bytes)")), msg.sender, _value, this, _extraData)) { revert(); }
        return true;
    }
}
