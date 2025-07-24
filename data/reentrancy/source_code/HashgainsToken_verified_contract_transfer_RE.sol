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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before completing the balance update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(bytes4(bytes32(sha3("onTokenReceived(address,uint256)"))), msg.sender, _value)` to notify the recipient
 * 2. Moved the recipient's balance update (`balances[_to] += _value`) to occur AFTER the external call
 * 3. Added conditional logic that only completes the transfer if the callback succeeds
 * 4. The sender's balance is decremented BEFORE the external call, creating an inconsistent state window
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * Transaction 1: Attacker calls transfer() to a malicious contract
 * - Sender balance is decremented immediately
 * - External call triggers attacker's onTokenReceived callback
 * - In callback, attacker can call transfer() again while sender balance is already reduced
 * - This creates a window where the same tokens can be transferred multiple times
 * 
 * Transaction 2: Attacker's callback function re-enters transfer()
 * - The original sender's balance check passes because it was already decremented
 * - Attacker can drain more tokens than the sender actually owns
 * - Each re-entrant call further reduces the sender's balance before the recipient balance is updated
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to control a contract at the recipient address
 * - The attacker must implement onTokenReceived callback to re-enter during the external call
 * - The exploitation happens across the call stack of multiple function invocations
 * - State accumulation occurs as each re-entrant call further manipulates balances
 * - Cannot be exploited in a single atomic transaction without the callback mechanism
 * 
 * This creates a realistic, production-like vulnerability where the external notification feature introduces a dangerous reentrancy vector that requires sophisticated multi-transaction exploitation.
 */
pragma solidity ^0.4.4;

contract Token {
    function totalSupply() constant returns (uint256 supply) {}
    function balanceOf(address _owner) constant returns (uint256 balance) {}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => uint256) balances; // ADDED to fix undeclared errors
    event Transfer(address indexed _from, address indexed _to, uint256 _value); // ADDED for base contract
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            // External call to notify recipient - creates reentrancy opportunity
            if (_to.call(bytes4(bytes32(sha3("onTokenReceived(address,uint256)"))), msg.sender, _value)) {
                // Only update recipient balance if callback succeeds
                balances[_to] += _value;
                Transfer(msg.sender, _to, _value);
                return true;
            } else {
                // Revert sender balance change if callback fails
                balances[msg.sender] += _value;
                return false;
            }
        } else { return false; }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {}
    function approve(address _spender, uint256 _value) returns (bool success) {}
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {}
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); // ADDED for base contract
}

contract HashgainsToken is Token {
    string public name;              
    uint8 public decimals;              
    string public symbol;                
    string public version = 'H1.0';
    uint256 public unitsOneEthCanBuy;    
    uint256 public totalEthInWei;        
    address public fundsWallet; 
    // mapping (address => uint256) balances; // Already inherited from Token
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
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
    constructor() public {
        balances[msg.sender] = 50000000000000000000000000;              
        totalSupply = 50000000000000000000000000;                       
        name = "HashgainsToken";                                   
        decimals = 18;                                              
        symbol = "HGS";                                            
        unitsOneEthCanBuy = 1000;                                  
        fundsWallet = msg.sender;                                  
    }
    function() payable{
        totalEthInWei = totalEthInWei + msg.value;
        uint256 amount = msg.value * unitsOneEthCanBuy;
        if (balances[fundsWallet] < amount) {
            return;
        }
        balances[fundsWallet] = balances[fundsWallet] - amount;
        balances[msg.sender] = balances[msg.sender] + amount;
        Transfer(fundsWallet, msg.sender, amount);
        fundsWallet.transfer(msg.value);                               
    }
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        if(!_spender.call(bytes4(bytes32(sha3("receiveApproval(address,uint256,address,bytes)"))), msg.sender, _value, this, _extraData)) { revert(); }
        return true;
    }
}