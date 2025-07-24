/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a timestamp dependence vulnerability in a time-locked token system. The vulnerability is stateful and multi-transaction: 1) Users must first call initiateLock() to lock tokens with a timestamp, 2) The locked state persists across transactions, 3) Users can only unlock tokens after calling unlockTokens() when the timestamp condition is met. Miners can manipulate block timestamps within a 900-second window, allowing them to unlock tokens earlier than intended by manipulating the 'now' variable. This requires multiple transactions and state persistence to exploit.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract KuangJinLian{
    /* Public variables of the token */
    string public standard = 'JinKuangLian 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    /* Time-locked transfer functionality */
    mapping (address => uint256) public lockedBalances;
    mapping (address => uint256) public lockTimestamps;
    
    event TokensLocked(address indexed owner, uint256 amount, uint256 lockTime);
    event TokensUnlocked(address indexed owner, uint256 amount);
    
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function KuangJinLian() {
        balanceOf[msg.sender] =  1200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1200000000 * 1000000000000000000;                        // Update total supply
        name = "KuangJinLian";                                   // Set the name for display purposes
        symbol = "KJL";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Initiate a time-locked balance for earning rewards */
    function initiateLock(uint256 _amount, uint256 _lockDuration) returns (bool success) {
        if (balanceOf[msg.sender] < _amount) throw;
        if (_lockDuration < 86400) throw; // Minimum 1 day lock
        
        balanceOf[msg.sender] -= _amount;
        lockedBalances[msg.sender] += _amount;
        lockTimestamps[msg.sender] = now + _lockDuration;
        
        TokensLocked(msg.sender, _amount, lockTimestamps[msg.sender]);
        return true;
    }
    
    /* Unlock tokens after lock period expires */
    function unlockTokens() returns (bool success) {
        if (lockedBalances[msg.sender] == 0) throw;
        if (now < lockTimestamps[msg.sender]) throw; // Still locked
        
        uint256 amount = lockedBalances[msg.sender];
        lockedBalances[msg.sender] = 0;
        lockTimestamps[msg.sender] = 0;
        balanceOf[msg.sender] += amount;
        
        TokensUnlocked(msg.sender, amount);
        return true;
    }
    
    /* Check if tokens can be unlocked */
    function canUnlock(address _owner) constant returns (bool) {
        return lockedBalances[_owner] > 0 && now >= lockTimestamps[_owner];
    }
    // === END FALLBACK INJECTION ===

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
