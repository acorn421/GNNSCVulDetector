/*
 * ===== SmartInject Injection Details =====
 * Function      : releaseLockedTokens
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The vulnerability requires multiple transactions to exploit: 1) First transaction calls lockTokens() to lock tokens with a future release time, 2) The state persists between transactions with lockedTokens and lockReleaseTime mappings, 3) Second transaction calls releaseLockedTokens() which uses 'now' (block.timestamp) that can be manipulated by miners within ~15 minutes, allowing premature release of locked tokens. The vulnerability is stateful because it depends on persistent state variables that track locked amounts and release times across multiple transactions.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-25
*/

pragma solidity ^0.4.19;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract ESVtoken{
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FIXED: Mappings for time-locked tokens moved to contract scope ===
    // State variables for time-locked tokens
    mapping (address => uint256) public lockedTokens;
    mapping (address => uint256) public lockReleaseTime;
    // === END FIXED ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function ESVtoken (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Lock tokens for a specified period
     * 
     * @param _amount The amount of tokens to lock
     * @param _lockDuration Duration in seconds to lock tokens
     */
    function lockTokens(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_lockDuration > 0);
        // Transfer tokens to locked balance
        balanceOf[msg.sender] -= _amount;
        lockedTokens[msg.sender] += _amount;
        // Set release time based on current block timestamp
        lockReleaseTime[msg.sender] = now + _lockDuration;
        return true;
    }
    /**
     * Release locked tokens after lock period expires
     * VULNERABILITY: Uses block.timestamp (now) which can be manipulated by miners
     */
    function releaseLockedTokens() public returns (bool success) {
        require(lockedTokens[msg.sender] > 0);
        // VULNERABLE: Miners can manipulate timestamp within ~15 minutes
        // This allows premature release of locked tokens
        require(now >= lockReleaseTime[msg.sender]);
        uint256 amount = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;
        balanceOf[msg.sender] += amount;
        return true;
    }
    /**
     * Extend lock period for already locked tokens
     * 
     * @param _additionalDuration Additional time in seconds to extend lock
     */
    function extendLockPeriod(uint256 _additionalDuration) public returns (bool success) {
        require(lockedTokens[msg.sender] > 0);
        require(_additionalDuration > 0);
        // Extend the lock period
        lockReleaseTime[msg.sender] += _additionalDuration;
        return true;
    }
    // === END FALLBACK INJECTION ===

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
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
