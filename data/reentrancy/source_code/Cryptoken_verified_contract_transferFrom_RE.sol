/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Added `pendingTransfers` and `transferInProgress` mappings to track ongoing transfers and accumulate state between transactions.
 * 
 * 2. **External Call Before State Updates**: Added a notification call to the recipient contract (`_to.call(...)`) that occurs BEFORE the critical state updates (balance and allowance modifications). This violates the Checks-Effects-Interactions pattern.
 * 
 * 3. **Persistent State Accumulation**: The `pendingTransfers` mapping accumulates pending transfer amounts that persist across transactions, creating opportunities for multi-transaction exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker approves a malicious contract to spend tokens
 * - Normal transferFrom calls accumulate state in `pendingTransfers`
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls transferFrom with a malicious recipient contract
 * - Function sets `transferInProgress[_from] = true` and increments `pendingTransfers[_from]`
 * - External call to malicious recipient triggers before state updates
 * 
 * **Transaction 3+ (Reentrant Exploitation):**
 * - Malicious recipient contract can call transferFrom again during the callback
 * - Since original state updates haven't occurred yet, balance checks still pass
 * - The `pendingTransfers` state from previous transactions enables the attacker to calculate how much has been "committed" but not yet processed
 * - Attacker can drain funds by repeatedly calling transferFrom during the callback window
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The `pendingTransfers` mapping accumulates state from multiple calls
 * 2. **Persistent Tracking**: `transferInProgress` flags persist between function calls
 * 3. **Callback Dependency**: Exploitation requires the external call to trigger, which may not happen in every transaction
 * 4. **Balance Preparation**: Attacker needs multiple transactions to set up appropriate balances and allowances to maximize exploitation
 * 
 * The vulnerability cannot be exploited in a single transaction because the state accumulation and callback mechanism require multiple function invocations to create the exploitable conditions.
 */
//Cryptoken
//Ȼ

pragma solidity ^0.4.11;

contract Token {
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
contract StandardToken is Token {
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => uint256) public pendingTransfers;
    mapping (address => bool) public transferInProgress;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            // Mark transfer as in progress to accumulate state
            transferInProgress[_from] = true;
            pendingTransfers[_from] += _value;
            
            // Notify recipient contract before state updates (vulnerable to reentrancy)
            if (isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
                require(callSuccess, "Token notification failed");
            }
            
            // State updates occur after external call - vulnerable window
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Clear transfer tracking
            transferInProgress[_from] = false;
            pendingTransfers[_from] -= _value;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    // Helper function to detect contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
contract Cryptoken is StandardToken {

    function () public {
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
        emit Approval(msg.sender, _spender, _value);

        if(!_spender.call(bytes4(keccak256("receiveApproval(address,uint256,address,bytes)")), msg.sender, _value, this, _extraData)) { revert(); }
        return true;
    }
}
