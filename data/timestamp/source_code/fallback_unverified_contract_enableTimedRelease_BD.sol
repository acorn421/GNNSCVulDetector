/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedRelease
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
 * This vulnerability introduces timestamp dependence in a multi-transaction token release mechanism. The vulnerability requires: 1) First calling enableTimedRelease() to lock tokens with a time delay, 2) Waiting for the specified time period, 3) Calling releaseTimedTokens() to unlock tokens. The vulnerability allows malicious miners to manipulate block timestamps to either prevent token release (by setting earlier timestamps) or allow premature release (by setting later timestamps within acceptable bounds). This creates a stateful vulnerability where the exploit depends on the accumulated state from multiple transactions and timestamp manipulation across different blocks.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract TIMESCORE {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Mapping to track time-locked tokens */
    mapping (address => uint256) public lockedTokens;
    mapping (address => uint256) public releaseTime;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function TIMESCORE(
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
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection

    /* Enable time-locked token release - must be called first */
    function enableTimedRelease(uint256 _amount, uint256 _releaseDelay) {
        if (balanceOf[msg.sender] < _amount) throw;
        if (lockedTokens[msg.sender] > 0) throw; // Already has locked tokens
        lockedTokens[msg.sender] = _amount;
        releaseTime[msg.sender] = now + _releaseDelay; // Vulnerable to timestamp manipulation
        balanceOf[msg.sender] -= _amount;
    }

    /* Release time-locked tokens - must be called after time passes */
    function releaseTimedTokens() {
        if (lockedTokens[msg.sender] == 0) throw; // No locked tokens
        if (now < releaseTime[msg.sender]) throw; // Still locked - vulnerable to timestamp manipulation
        uint256 tokensToRelease = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;
        releaseTime[msg.sender] = 0;
        balanceOf[msg.sender] += tokensToRelease;
    }

    /* Check if tokens can be released */
    function canReleaseTokens(address _holder) returns (bool) {
        if (lockedTokens[_holder] == 0) return false;
        return now >= releaseTime[_holder]; // Vulnerable to timestamp manipulation
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
