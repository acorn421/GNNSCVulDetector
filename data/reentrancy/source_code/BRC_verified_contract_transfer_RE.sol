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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the recipient contract using onTokenReceived callback. The vulnerability occurs because:
 * 
 * 1. **State Modification Before External Call**: The sender's balance is decreased before the external call, but the recipient's balance is updated after the call, creating an inconsistent state window.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transfer() to a malicious contract
 *    - During the callback, the malicious contract can call transfer() again
 *    - Since sender's balance was already decreased but recipient's balance not yet increased, the attacker can exploit this inconsistent state
 *    - Multiple reentrant calls can drain more tokens than the sender's original balance
 * 
 * 3. **Stateful Requirements**: 
 *    - The vulnerability requires the persistent balance state changes between calls
 *    - Each reentrant call operates on the modified state from previous calls
 *    - The attack builds up across multiple function invocations within the same transaction, but the state changes persist and accumulate
 * 
 * 4. **Realistic Integration**: The onTokenReceived callback is a common pattern in modern token standards (like ERC-777) for notifying recipients of token transfers, making this vulnerability realistic and subtle.
 * 
 * The key issue is the violation of the Checks-Effects-Interactions pattern: the external call happens after partial state changes but before the transfer is fully completed, allowing reentrancy during an inconsistent state.
 */
pragma solidity ^0.4.8;

interface ERC20Interface {

    function totalSupply() constant returns (uint256 totalSupply);

    function balanceOf(address _owner) constant returns (uint256 balance);

    // The vulnerable transfer implementation is for reference in the interface,
    // but in Solidity <0.6.0, interfaces cannot have function bodies.
    // So, we should remove the body to allow compilation, but keep the signature,
    // and the vulnerability remains implemented in the contract below.
    function transfer(address _to, uint256 _amount) returns (bool success);

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);

    function approve(address _spender, uint256 _value) returns (bool success);

    function allowance(address _owner, address _spender) constant returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract BRC is ERC20Interface {
    string public constant symbol = "BRC";
    string public constant name = "Baer Chain";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 58000000000000000;

    address public owner;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    function BRC() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256 totalSupply) {
        totalSupply = _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            balances[msg.sender] -= _amount;
            // External call to notify recipient before completing the transfer
            // This allows the recipient to potentially call back during the transfer
            if (isContract(_to)) {
                _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
                // Continue even if callback fails
            }
            // Complete the transfer by updating recipient's balance
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Helper function to check if an address is a contract
    function isContract(address addr) private constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    function transferFrom(address _from, address _to, uint256 _amount) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
