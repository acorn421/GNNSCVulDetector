/*
 * ===== SmartInject Injection Details =====
 * Function      : claimDailyReward
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
 * This vulnerability involves a timestamp dependence attack on the daily reward claiming system. The contract uses block.timestamp (now) to determine when users can claim daily rewards and maintain reward streaks. Attackers can exploit this by:
 * 
 * 1. First transaction: Claim initial daily reward, establishing lastRewardClaim timestamp
 * 2. Wait for mining opportunity or coordinate with miners 
 * 3. Second transaction: Mine a block with manipulated timestamp that appears to be 24+ hours later
 * 4. Third transaction: Claim reward again with inflated streak bonus
 * 5. Repeat process: Continue manipulating timestamps to maintain artificial streaks and claim rewards early
 * 
 * The vulnerability is stateful because it relies on the persistent storage of lastRewardClaim and rewardStreak mappings across multiple transactions. The exploit requires multiple function calls over time to build up significant reward streaks and accumulate tokens. Each successful manipulation increases the streak counter, making future rewards more valuable with streak bonuses.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract SuperNodeCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 2;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Daily reward system variables (moved to contract-level scope)
    mapping (address => uint256) public lastRewardClaim;
    mapping (address => uint256) public rewardStreak;
    uint256 public constant DAILY_REWARD = 100;
    uint256 public constant STREAK_BONUS = 50;
    uint256 public constant SECONDS_PER_DAY = 86400;
    // === END DECLARATION ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TokenERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = 1000000000000;  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "SuperNodeCoin";                                   // Set the name for display purposes
        symbol = "SPNC";                               // Set the symbol for display purposes
    }
    
    /**
     * Claim daily reward tokens
     * 
     * Users can claim daily rewards with streak bonuses
     * Vulnerable to timestamp manipulation attacks
     */
    function claimDailyReward() public returns (bool success) {
        uint256 currentTime = now;
        uint256 lastClaim = lastRewardClaim[msg.sender];
        
        // First time claiming
        if (lastClaim == 0) {
            lastRewardClaim[msg.sender] = currentTime;
            rewardStreak[msg.sender] = 1;
            balanceOf[msg.sender] += DAILY_REWARD;
            totalSupply += DAILY_REWARD;
            Transfer(0x0, msg.sender, DAILY_REWARD);
            return true;
        }
        
        // Check if 24 hours have passed
        uint256 timeSinceLastClaim = currentTime - lastClaim;
        
        // Vulnerable: Using block.timestamp for critical logic
        if (timeSinceLastClaim >= SECONDS_PER_DAY) {
            uint256 reward = DAILY_REWARD;
            
            // Check if streak continues (claimed within 48 hours)
            if (timeSinceLastClaim <= SECONDS_PER_DAY * 2) {
                rewardStreak[msg.sender] += 1;
                // Add streak bonus
                reward += (rewardStreak[msg.sender] - 1) * STREAK_BONUS;
            } else {
                // Streak broken, reset to 1
                rewardStreak[msg.sender] = 1;
            }
            
            lastRewardClaim[msg.sender] = currentTime;
            balanceOf[msg.sender] += reward;
            totalSupply += reward;
            Transfer(0x0, msg.sender, reward);
            return true;
        }
        
        return false;
    }
    
    /**
     * Get time until next reward claim
     * 
     * Returns seconds until next reward can be claimed
     */
    function getTimeUntilNextReward() public view returns (uint256) {
        uint256 lastClaim = lastRewardClaim[msg.sender];
        if (lastClaim == 0) {
            return 0;
        }
        
        uint256 timeSinceLastClaim = now - lastClaim;
        if (timeSinceLastClaim >= SECONDS_PER_DAY) {
            return 0;
        }
        
        return SECONDS_PER_DAY - timeSinceLastClaim;
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        Approval(msg.sender, _spender, _value);
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
