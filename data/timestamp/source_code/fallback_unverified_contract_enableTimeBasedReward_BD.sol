/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeBasedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a time-based reward system. The vulnerability is stateful and requires multiple transactions to exploit: 1) User must first call registerForRewards() to set their lastRewardTime, 2) Time must pass (or be manipulated by miners), 3) User calls claimTimeBasedRewards() to exploit the manipulated timestamp. The vulnerability relies on persistent state (lastRewardTime, rewardAccumulated) and cannot be exploited in a single transaction since it requires the passage of time between registration and claiming.
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TCN {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-based reward system state variables
    mapping (address => uint256) public lastRewardTime;
    mapping (address => uint256) public rewardAccumulated;
    uint256 public rewardRate = 10; // tokens per hour
    bool public rewardSystemActive = false;
    uint256 public rewardActivationTime;
    // === END MAPPINGS FOR REWARD ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TCN()
        public
    {
        totalSupply = 100000000000000000;                     // Update total supply with the decimal amount
        balanceOf[msg.sender] = 100000000000000000;           // Give the creator all initial tokens
        name = "TrentCoin";                                   // Set the name for display purposes
        symbol = "TCN";                                       // Set the symbol for display purposes
    }

    /**
     * Enable time-based reward system
     * 
     * Activates the reward system that allows users to claim rewards based on time
     */
    function enableTimeBasedReward() public {
        require(msg.sender == address(this) || balanceOf[msg.sender] > 0); // Only token holders can enable
        rewardSystemActive = true;
        rewardActivationTime = now;
    }
    
    /**
     * Register for rewards
     * 
     * Users must register first before claiming rewards
     */
    function registerForRewards() public {
        require(rewardSystemActive); // Reward system must be active
        require(balanceOf[msg.sender] > 0); // Must hold tokens to register
        lastRewardTime[msg.sender] = now;
    }
    
    /**
     * Calculate pending rewards
     * 
     * Calculate how many reward tokens a user can claim based on time elapsed
     */
    function calculatePendingRewards(address _user) public view returns (uint256) {
        if (!rewardSystemActive || lastRewardTime[_user] == 0) {
            return 0;
        }
        
        uint256 timeElapsed = now - lastRewardTime[_user];
        uint256 hoursElapsed = timeElapsed / 3600; // Convert seconds to hours
        uint256 pendingReward = hoursElapsed * rewardRate * balanceOf[_user] / 1000000; // Proportional to balance
        
        return pendingReward;
    }
    
    /**
     * Claim time-based rewards
     * 
     * Users can claim accumulated rewards based on time since last claim
     */
    function claimTimeBasedRewards() public {
        require(rewardSystemActive); // Reward system must be active
        require(lastRewardTime[msg.sender] > 0); // Must register first
        require(now > lastRewardTime[msg.sender]); // Cannot claim in same block
        
        uint256 pendingReward = calculatePendingRewards(msg.sender);
        require(pendingReward > 0); // No rewards to claim
        
        // Vulnerability: Miners can manipulate timestamp to claim more rewards
        // This creates a multi-transaction vulnerability where:
        // 1. User registers for rewards
        // 2. Miner manipulates timestamp in subsequent blocks
        // 3. User claims inflated rewards
        
        rewardAccumulated[msg.sender] += pendingReward;
        lastRewardTime[msg.sender] = now;
        
        // Create new tokens for rewards (inflationary)
        totalSupply += pendingReward;
        balanceOf[msg.sender] += pendingReward;
        
        Transfer(0x0, msg.sender, pendingReward);
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
