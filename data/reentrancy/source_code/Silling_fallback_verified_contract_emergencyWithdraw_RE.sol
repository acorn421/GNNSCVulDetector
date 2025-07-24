/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability where users must first call requestWithdrawal() to set up pending withdrawal state, then call emergencyWithdraw() which makes an external call before updating state variables. The vulnerability requires multiple transactions and persistent state to exploit - an attacker must first request a withdrawal, then use a malicious contract to recursively call emergencyWithdraw() during the external call to drain funds.
 */
pragma solidity ^0.4.24;

contract Silling {

    string public constant name = "SILLING";
    string public constant symbol = "SLN";
    uint8 public constant decimals = 18;  

    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    event Transfer(address indexed from, address indexed to, uint tokens);

    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;
    uint256 totalSupply_;

    using SafeMath for uint256;

    // === FALLBACK INJECTION: Reentrancy ===
    // The injected vulnerability and related mappings:
    mapping(address => uint256) pendingWithdrawals;
    mapping(address => bool) withdrawalActive;

    constructor() public {  
        totalSupply_ = 500000000 * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply_;
    }  

    function requestWithdrawal(uint256 amount) public returns (bool) {
        require(amount <= balances[msg.sender], "Insufficient balance");
        require(!withdrawalActive[msg.sender], "Withdrawal already active");
        pendingWithdrawals[msg.sender] = amount;
        withdrawalActive[msg.sender] = true;
        return true;
    }

    function emergencyWithdraw() public {
        require(withdrawalActive[msg.sender], "No active withdrawal");
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        uint256 amount = pendingWithdrawals[msg.sender];
        // Vulnerable: External call before state update
        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] = balances[msg.sender].sub(amount);
            pendingWithdrawals[msg.sender] = 0;
            withdrawalActive[msg.sender] = false;
        }
    }
    // === END FALLBACK INJECTION ===

    function totalSupply() public view returns (uint256) {
        return totalSupply_;
    }
    
    function balanceOf(address tokenOwner) public view returns (uint) {
        return balances[tokenOwner];
    }

    function transfer(address receiver, uint numTokens) public returns (bool) {
        require(numTokens <= balances[msg.sender]);
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[receiver] = balances[receiver].add(numTokens);
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }

    function approve(address delegate, uint numTokens) public returns (bool) {
        allowed[msg.sender][delegate] = numTokens;
        emit Approval(msg.sender, delegate, numTokens);
        return true;
    }

    function allowance(address owner, address delegate) public view returns (uint) {
        return allowed[owner][delegate];
    }

    function transferFrom(address owner, address buyer, uint numTokens) public returns (bool) {
        require(numTokens <= balances[owner]);    
        require(numTokens <= allowed[owner][msg.sender]);
        balances[owner] = balances[owner].sub(numTokens);
        allowed[owner][msg.sender] = allowed[owner][msg.sender].sub(numTokens);
        balances[buyer] = balances[buyer].add(numTokens);
        emit Transfer(owner, buyer, numTokens);
        return true;
    }
}

library SafeMath { 
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
      assert(b <= a);
      return a - b;
    }
    
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a + b;
      assert(c >= a);
      return c;
    }
}