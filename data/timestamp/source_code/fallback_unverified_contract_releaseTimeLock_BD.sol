/*
 * ===== SmartInject Injection Details =====
 * Function      : releaseTimeLock
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
 * This injection introduces a timestamp dependence vulnerability through a time-locked token release mechanism. The vulnerability is stateful and requires multiple transactions: (1) lockTokens() to set the release time based on block.timestamp, and (2) releaseTimeLock() or emergencyRelease() to check against the potentially manipulated timestamp. Miners can manipulate block.timestamp within certain bounds to either delay or accelerate the release of locked tokens, potentially bypassing intended lock periods or penalty mechanisms.
 */
pragma solidity ^0.4.10;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract RichTitaniunCoin {
    /* Public variables of the token */
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
    // Time-locked release mechanism for tokens
    mapping (address => uint256) public timeLockedBalance;
    mapping (address => uint256) public releaseTime;
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function RichTitaniunCoin() public {
        balanceOf[msg.sender] = 820000000000; // Give the creator all initial tokens
        totalSupply = 820000000000;                        // Update total supply
        name = "Rich Titaniun Coin";                                   // Set the name for display purposes
        symbol = "RTC";                               // Set the symbol for display purposes
        decimals = 4;                            // Amount of decimals for display purposes
    }

    /// @notice Lock tokens for a specific time period
    /// @param _amount Amount of tokens to lock
    /// @param _lockDuration Duration in seconds to lock tokens
    function lockTokens(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_lockDuration > 0);
        balanceOf[msg.sender] -= _amount;
        timeLockedBalance[msg.sender] += _amount;
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        releaseTime[msg.sender] = block.timestamp + _lockDuration;
        return true;
    }

    /// @notice Release time-locked tokens if lock period has expired
    function releaseTimeLock() public returns (bool success) {
        require(timeLockedBalance[msg.sender] > 0);
        // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
        require(block.timestamp >= releaseTime[msg.sender]);
        uint256 lockedAmount = timeLockedBalance[msg.sender];
        timeLockedBalance[msg.sender] = 0;
        releaseTime[msg.sender] = 0;
        balanceOf[msg.sender] += lockedAmount;
        return true;
    }

    /// @notice Emergency release with penalty (vulnerable to timestamp manipulation)
    function emergencyRelease() public returns (bool success) {
        require(timeLockedBalance[msg.sender] > 0);
        uint256 lockedAmount = timeLockedBalance[msg.sender];
        uint256 penalty = 0;
        // Vulnerable: Early release penalty calculation depends on timestamp
        if (block.timestamp < releaseTime[msg.sender]) {
            // Apply 10% penalty for early release
            penalty = (lockedAmount * 10) / 100;
        }
        timeLockedBalance[msg.sender] = 0;
        releaseTime[msg.sender] = 0;
        balanceOf[msg.sender] += (lockedAmount - penalty);
        // Penalty tokens are burned
        if (penalty > 0) {
            totalSupply -= penalty;
            Burn(msg.sender, penalty);
        }
        return true;
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
