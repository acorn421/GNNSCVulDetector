/*
 * ===== SmartInject Injection Details =====
 * Function      : createTimeLockedReward
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
 * This vulnerability introduces a timestamp dependence issue in a time-locked reward system. The vulnerability is stateful and requires multiple transactions: (1) First transaction calls createTimeLockedReward() to lock tokens and set a future unlock time based on block.timestamp, (2) Second transaction calls claimTimeLockedReward() to claim rewards after the lock period. The vulnerability allows miners to manipulate block.timestamp to either prevent legitimate users from claiming rewards or allow early claiming, affecting the reward distribution mechanism across multiple transactions.
 */
pragma solidity ^0.4.21;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract RNG {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked reward system state variables
    mapping(address => uint256) public rewardLockTime;
    mapping(address => uint256) public pendingReward;
    uint256 public rewardMultiplier = 2;
    // === END variable injection ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function RNG()
        public
    {
        totalSupply = 1000000000000000000000000000;                             // Total supply with the decimal amount
        balanceOf[msg.sender] = 1000000000000000000000000000;                   // All initial tokens
        name = "Ringside";                                                      // The name for display purposes
        symbol = "RNG";                                                         // The symbol for display purposes
    }

    /**
     * Create a time-locked reward for token holders
     * Users can lock their tokens for a period and earn rewards
     * 
     * @param _lockDuration Duration in seconds to lock tokens
     * @param _amount Amount of tokens to lock for rewards
     */
    function createTimeLockedReward(uint256 _lockDuration, uint256 _amount) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_lockDuration >= 86400); // Minimum 1 day lock
        require(rewardLockTime[msg.sender] == 0); // No existing lock

        // Lock tokens by reducing balance temporarily
        balanceOf[msg.sender] -= _amount;

        // Set unlock time using block.timestamp - VULNERABLE TO TIMESTAMP MANIPULATION
        rewardLockTime[msg.sender] = block.timestamp + _lockDuration;

        // Calculate pending reward based on amount and duration
        pendingReward[msg.sender] = (_amount * rewardMultiplier * _lockDuration) / 86400;

        return true;
    }

    /**
     * Claim time-locked rewards after lock period expires
     * This function can only be called after the lock time has passed
     */
    function claimTimeLockedReward() public returns (bool success) {
        require(rewardLockTime[msg.sender] > 0); // Must have active lock
        require(pendingReward[msg.sender] > 0); // Must have pending reward

        // VULNERABLE: Uses block.timestamp for time comparison
        // Miners can manipulate timestamp to allow early claiming
        require(block.timestamp >= rewardLockTime[msg.sender]); // Check if lock period expired

        uint256 reward = pendingReward[msg.sender];

        // Clear the lock and reward state
        rewardLockTime[msg.sender] = 0;
        pendingReward[msg.sender] = 0;

        // Mint new tokens as reward (increases total supply)
        totalSupply += reward;
        balanceOf[msg.sender] += reward;

        Transfer(0x0, msg.sender, reward);
        return true;
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
