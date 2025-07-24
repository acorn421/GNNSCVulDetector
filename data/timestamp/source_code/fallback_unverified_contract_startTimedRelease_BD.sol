/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedRelease
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
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The vulnerability involves a time-locked token release system where users can lock tokens for a specific duration and then release them after the time period expires. The vulnerability lies in the use of 'now' (block.timestamp) which can be manipulated by miners within certain bounds. To exploit this vulnerability, an attacker would need to: 1) First call startTimedRelease() to lock tokens with a specific duration, 2) Wait for the timestamp condition, 3) Call completeTimedRelease() where miners can potentially manipulate the timestamp to allow early release or prevent release. This creates a stateful, multi-transaction vulnerability that persists state between calls and requires multiple function invocations to complete the exploit.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract SIGTOKEN {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked token release system
    mapping (address => uint256) public timedReleaseAmount;
    mapping (address => uint256) public timedReleaseTimestamp;

    event TimedReleaseStarted(address indexed holder, uint256 amount, uint256 releaseTime);
    event TimedReleaseCompleted(address indexed holder, uint256 amount);
    // === END OF FALLBACK INJECTION STATE VARS AND EVENTS ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function SIGTOKEN(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Start a timed release of tokens
     * Locks tokens for a specified duration and allows release after that time
     * 
     * @param _amount The amount of tokens to lock
     * @param _lockDuration Duration in seconds to lock the tokens
     */
    function startTimedRelease(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_amount > 0);
        require(_lockDuration > 0);
        require(timedReleaseAmount[msg.sender] == 0); // No existing timed release
        // Lock the tokens by reducing balance
        balanceOf[msg.sender] -= _amount;
        timedReleaseAmount[msg.sender] = _amount;
        timedReleaseTimestamp[msg.sender] = now + _lockDuration;
        TimedReleaseStarted(msg.sender, _amount, timedReleaseTimestamp[msg.sender]);
        return true;
    }

    /**
     * Complete a timed release of tokens
     * Releases locked tokens back to the holder if the time lock has expired
     * VULNERABILITY: Uses 'now' (block.timestamp) which can be manipulated by miners
     * The multi-transaction vulnerability requires:
     * 1. First call startTimedRelease() to lock tokens
     * 2. Wait for timestamp condition
     * 3. Call completeTimedRelease() to unlock - miners can manipulate timestamp
     */
    function completeTimedRelease() public returns (bool success) {
        require(timedReleaseAmount[msg.sender] > 0);
        require(now >= timedReleaseTimestamp[msg.sender]); // VULNERABLE: timestamp dependence
        uint256 releaseAmount = timedReleaseAmount[msg.sender];
        timedReleaseAmount[msg.sender] = 0;
        timedReleaseTimestamp[msg.sender] = 0;
        balanceOf[msg.sender] += releaseAmount;
        TimedReleaseCompleted(msg.sender, releaseAmount);
        return true;
    }

    /**
     * Check if timed release is ready for completion
     * Helper function to check timestamp condition
     */
    function isTimedReleaseReady(address _holder) public view returns (bool) {
        return timedReleaseAmount[_holder] > 0 && now >= timedReleaseTimestamp[_holder];
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
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
     * Send `_value` tokens to `_to` on behalf of `_from`
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
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
     * Destroy tokens from other account
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