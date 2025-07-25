/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokensTemporary
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The exploit requires: 1) First transaction: User locks tokens with lockTokensTemporary(), setting an expiry time based on 'now' 2) State persists: locked tokens and expiry time stored in contract state 3) Second transaction: User attempts to unlock with unlockTemporaryTokens(), which depends on timestamp comparison. A malicious miner can manipulate block timestamps to either prevent early unlocking or allow premature unlocking, creating an unfair advantage. The vulnerability is stateful because it requires persistent state between transactions and cannot be exploited in a single call.
 */
/**NEXBIT Coin (NBC)
 Visit project : https://nexbit.io */


pragma solidity ^0.4.11;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      revert();
    }
  }
}
contract NEXBITCoin is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to track temporary locks (must be contract-level, not inside function)
    mapping (address => uint256) public temporaryLockOf;
    mapping (address => uint256) public lockExpiryTime;
    
    event TemporaryLock(address indexed from, uint256 value, uint256 unlockTime);
    event TemporaryUnlock(address indexed from, uint256 value);
    // === END FALLBACK INJECTION ===

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function NEXBITCoin(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Lock tokens temporarily for a specific duration */
    function lockTokensTemporary(uint256 _value, uint256 _durationMinutes) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        if (_value <= 0) revert();
        if (_durationMinutes == 0) revert();
        
        // Move tokens from balance to temporary lock
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        temporaryLockOf[msg.sender] = SafeMath.safeAdd(temporaryLockOf[msg.sender], _value);
        
        // Set expiry time based on current timestamp - VULNERABLE TO TIMESTAMP MANIPULATION
        lockExpiryTime[msg.sender] = now + (_durationMinutes * 60);
        
        TemporaryLock(msg.sender, _value, lockExpiryTime[msg.sender]);
        return true;
    }

    /* Unlock temporarily locked tokens after expiry */
    function unlockTemporaryTokens() returns (bool success) {
        if (temporaryLockOf[msg.sender] <= 0) revert();
        
        // VULNERABLE: Relies on timestamp comparison - miners can manipulate
        if (now < lockExpiryTime[msg.sender]) revert();
        
        uint256 unlockAmount = temporaryLockOf[msg.sender];
        temporaryLockOf[msg.sender] = 0;
        lockExpiryTime[msg.sender] = 0;
        
        // Move tokens back to balance
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], unlockAmount);
        
        TemporaryUnlock(msg.sender, unlockAmount);
        return true;
    }

    /* Emergency unlock for owner - bypasses time check */
    function emergencyUnlockFor(address _user) returns (bool success) {
        if (msg.sender != owner) revert();
        if (temporaryLockOf[_user] <= 0) revert();
        
        uint256 unlockAmount = temporaryLockOf[_user];
        temporaryLockOf[_user] = 0;
        lockExpiryTime[_user] = 0;
        
        balanceOf[_user] = SafeMath.safeAdd(balanceOf[_user], unlockAmount);
        
        TemporaryUnlock(_user, unlockAmount);
        return true;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) {
        if(msg.sender != owner)revert();
        owner.transfer(amount);
    }

    // can not accept ether
    function() {
revert();    }
}