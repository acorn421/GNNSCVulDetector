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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * **Transaction 2**: Victim calls `transfer()` to the malicious contract, which triggers the callback before balances are updated
 * **Transaction 3+**: During the callback, the malicious contract can call other functions like `transferFrom()` or additional `transfer()` calls using the outdated state
 * 
 * The vulnerability is multi-transaction because:
 * 1. The attacker must first deploy and prepare the malicious contract (Transaction 1)
 * 2. The victim must initiate the transfer (Transaction 2) 
 * 3. The exploit happens during the callback when the attacker can make additional calls using inconsistent state
 * 4. The accumulated effect of multiple reentrancy calls across the callback chain creates the exploitable condition
 * 
 * This creates a classic reentrancy pattern where external calls happen before state updates, and the vulnerability requires the setup and execution across multiple transactions rather than being exploitable in a single atomic transaction.
 */
pragma solidity ^0.4.8;

interface ERC20Interface {

    function totalSupply() constant returns (uint256);
    
    function balanceOf(address _owner) constant returns (uint256);
    
    function transfer(address _to, uint256 _amount) returns (bool success);
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    
    function approve(address _spender, uint256 _value) returns (bool success);
    
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract PETRO is ERC20Interface {
    string public constant symbol = "PTR";
    string public constant name = "PETRO";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 10000000000000000;

    address public owner;

    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }

    constructor() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256) {
        return balances[_owner];
    }

    // Vulnerable transfer (reentrancy) function
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient before state update (reentrancy window)
            if (isContract(_to)) {
                bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
                _to.call(selector, msg.sender, _amount);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success) {
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

    // Helper function to check if address is a contract
    function isContract(address addr) private constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}