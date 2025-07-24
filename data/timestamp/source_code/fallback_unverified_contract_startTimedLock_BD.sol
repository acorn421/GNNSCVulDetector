/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability through a timed token locking mechanism. Users can lock tokens for a specified duration, but the unlock mechanism relies on 'now' (block.timestamp) which can be manipulated by miners. The vulnerability is stateful and multi-transaction because: 1) Users must first call startTimedLock() to lock tokens and set a timestamp, 2) The state persists between transactions with locked amounts and timestamps stored, 3) Users must later call unlockTokens() to retrieve tokens, 4) Miners can manipulate the timestamp during the unlock transaction to allow early unlocking, bypassing the intended lock period. This creates a multi-step exploitation requiring state persistence across transactions.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables must be declared at contract level, not inside constructor
    mapping(address => uint256) public lockAmounts;
    mapping(address => uint256) public lockTimestamps;
    mapping(address => bool) public lockActive;
    
    event TokensLocked(address indexed user, uint256 amount, uint256 unlockTime);
    event TokensUnlocked(address indexed user, uint256 amount);

    constructor() public {  
        totalSupply_ = 500000000 * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply_;
    }  

    function startTimedLock(uint256 amount, uint256 lockDurationMinutes) public returns (bool) {
        require(amount <= balances[msg.sender], "Insufficient balance");
        require(amount > 0, "Amount must be greater than 0");
        require(!lockActive[msg.sender], "Lock already active");
        require(lockDurationMinutes >= 1, "Lock duration must be at least 1 minute");

        // Transfer tokens to lock
        balances[msg.sender] = balances[msg.sender].sub(amount);
        lockAmounts[msg.sender] = amount;

        // Set unlock time based on current timestamp - VULNERABLE to timestamp manipulation
        lockTimestamps[msg.sender] = now + (lockDurationMinutes * 60);
        lockActive[msg.sender] = true;

        emit TokensLocked(msg.sender, amount, lockTimestamps[msg.sender]);
        return true;
    }

    function unlockTokens() public returns (bool) {
        require(lockActive[msg.sender], "No active lock found");

        // VULNERABLE: Miners can manipulate timestamp to unlock early
        // This requires multiple transactions - lock first, then unlock
        require(now >= lockTimestamps[msg.sender], "Lock period not expired");

        uint256 amount = lockAmounts[msg.sender];

        // Reset lock state
        lockActive[msg.sender] = false;
        lockAmounts[msg.sender] = 0;
        lockTimestamps[msg.sender] = 0;

        // Return tokens to user
        balances[msg.sender] = balances[msg.sender].add(amount);

        emit TokensUnlocked(msg.sender, amount);
        return true;
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