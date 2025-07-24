/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedUnlock
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
 * This injection adds a timed unlock mechanism that relies on block.timestamp (now) for critical timing operations. The vulnerability is stateful and multi-transaction: 1) User calls startTimedUnlock() to initiate the unlock process with a delay, 2) The contract stores the unlock timestamp in state, 3) User must wait for the time period to pass, 4) User calls claimUnlockedTokens() to receive additional tokens. The vulnerability allows miners to manipulate the timestamp within reasonable bounds (~15 minutes) to either delay or accelerate the unlock process, potentially allowing premature token claiming or preventing legitimate claims.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WoNiuBi{
    /* Public variables of the token */
    string public standard = 'WoNiuBi 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Timed unlock mechanism for tokens */
    mapping (address => uint256) public unlockedAmount;
    mapping (address => uint256) public unlockTimestamp;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function WoNiuBi() {
        balanceOf[msg.sender] =  3681391186 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  3681391186 * 1000000000000000000;                        // Update total supply
        name = "WoNiuBi";                                   // Set the name for display purposes
        symbol = "WNB";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Start a timed unlock process */
    function startTimedUnlock(uint256 _amount, uint256 _unlockDelay) {
        if (balanceOf[msg.sender] < _amount) throw;
        if (_unlockDelay < 1 minutes) throw;
        
        unlockedAmount[msg.sender] = _amount;
        unlockTimestamp[msg.sender] = now + _unlockDelay;
    }
    
    /* Claim unlocked tokens */
    function claimUnlockedTokens() {
        if (unlockedAmount[msg.sender] == 0) throw;
        if (now < unlockTimestamp[msg.sender]) throw;
        
        uint256 amount = unlockedAmount[msg.sender];
        unlockedAmount[msg.sender] = 0;
        unlockTimestamp[msg.sender] = 0;
        
        // Vulnerability: Relying on block.timestamp for critical timing
        // Miners can manipulate timestamp within ~900 seconds
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

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
