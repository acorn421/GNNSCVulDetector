/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimedBonus
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
 * This function introduces a timestamp dependence vulnerability where malicious miners can manipulate block timestamps to claim bonuses more frequently than intended. The vulnerability is stateful and multi-transaction because: 1) It requires multiple calls to claimTimedBonus() to accumulate significant bonus amounts, 2) State persists between transactions via lastBonusClaimTime and bonusClaimCount mappings, 3) The bonus amount increases with each claim, making repeated exploitation more profitable. A miner could manipulate timestamps across multiple blocks to repeatedly claim bonuses, with each claim being worth more than the previous due to the multiplier effect.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WallCoin {
    /* Public variables of the token */
    string public standard = 'WallCoin 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timed bonus claim system - users can claim bonuses at intervals
    mapping (address => uint256) public lastBonusClaimTime;
    mapping (address => uint256) public bonusClaimCount;
    uint256 public bonusClaimInterval = 86400; // 24 hours in seconds
    uint256 public bonusAmount = 100 * 1000000000000000000; // 100 WLC

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function WallCoin() {
        balanceOf[msg.sender] = 38000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 38000000 * 1000000000000000000;                        // Update total supply
        name = "WallCoin";                                   // Set the name for display purposes
        symbol = "WLC";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    function claimTimedBonus() returns (bool success) {
        // Check if enough time has passed since last claim
        if (now - lastBonusClaimTime[msg.sender] < bonusClaimInterval) throw;
        // Update claim tracking
        lastBonusClaimTime[msg.sender] = now;
        bonusClaimCount[msg.sender] += 1;
        // Calculate bonus based on claim count (increases over time)
        uint256 totalBonus = bonusAmount * bonusClaimCount[msg.sender];
        // Mint bonus tokens to user
        balanceOf[msg.sender] += totalBonus;
        totalSupply += totalBonus;
        Transfer(0x0, msg.sender, totalBonus);
        return true;
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
