/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimedRelease
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
 * This vulnerability introduces a timestamp dependence issue in a timed token release mechanism. The vulnerability is stateful and requires multiple transactions to exploit: (1) First, a user must call initiateTimedRelease() to lock tokens with a specific duration, creating persistent state in lockedTokens and releaseTime mappings. (2) Then, in a separate transaction, the user calls releaseTimedTokens() to claim the locked tokens. The vulnerability exists because the contract relies on block.timestamp for critical timing logic, which can be manipulated by miners within certain bounds. Miners can influence when tokens become available for release, potentially allowing early or delayed access to locked funds. This creates a multi-transaction attack vector where the state persists between the locking and releasing operations, and the timing manipulation affects the entire duration of the lock period.
 */
pragma solidity ^0.4.13;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract MINEX {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timed release mechanism for locked tokens
    mapping (address => uint256) public lockedTokens;
    mapping (address => uint256) public releaseTime;
    // === END FALLBACK INJECTION ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function MINEX() public {
        balanceOf[msg.sender] = 2999029096950000;              // Give the creator all initial tokens
        totalSupply = 2999029096950000;                        // Update total supply
        name = 'MINEX';                                   // Set the name for display purposes
        symbol = 'MINEX';                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /**
     * Initiate a timed release of tokens
     *
     * Locks tokens for a specified duration before they can be released
     *
     * @param _amount The amount of tokens to lock
     * @param _duration Duration in seconds to lock the tokens
     */
    function initiateTimedRelease(uint256 _amount, uint256 _duration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_duration > 0);
        balanceOf[msg.sender] -= _amount;
        lockedTokens[msg.sender] += _amount;
        // Vulnerable: Using block.timestamp for critical timing logic
        releaseTime[msg.sender] = block.timestamp + _duration;
        return true;
    }

    /**
     * Release locked tokens after the time period has passed
     *
     * Allows users to claim their locked tokens once the release time has been reached
     */
    function releaseTimedTokens() public returns (bool success) {
        require(lockedTokens[msg.sender] > 0);
        // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
        require(block.timestamp >= releaseTime[msg.sender]);
        uint256 amount = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;
        releaseTime[msg.sender] = 0;
        balanceOf[msg.sender] += amount;
        return true;
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other ccount
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
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