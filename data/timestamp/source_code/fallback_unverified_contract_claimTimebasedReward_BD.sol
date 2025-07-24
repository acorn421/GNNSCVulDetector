/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimebasedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The vulnerability is stateful because it depends on persistent state variables (lastRewardClaim, rewardMultiplier) that track user interactions over time. An attacker must: 1) First register for rewards, 2) Increase their multiplier over time, 3) Finally claim rewards. The vulnerability allows miners to manipulate block timestamps to artificially accelerate reward claims or manipulate the time-based calculations. The exploitation requires multiple transactions executed over time periods, making it a multi-transaction vulnerability that cannot be exploited in a single call.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract BugisContract {
    
    string public name = "Bugis";
    string public symbol = "BGS";
    uint8 public decimals = 18;
    
    uint256 public initialSupply = 600000;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Time-based reward system state variables
    mapping (address => uint256) public lastRewardClaim;
    mapping (address => uint256) public rewardMultiplier;
    uint256 public rewardCooldownPeriod = 3600; // 1 hour cooldown
    uint256 public baseRewardAmount = 100;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function BugisContract() public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
    }

    /**
     * Register for time-based rewards
     * 
     * Users must register first before claiming rewards
     */
    function registerForRewards() public returns (bool success) {
        require(lastRewardClaim[msg.sender] == 0, "Already registered");
        lastRewardClaim[msg.sender] = now;
        rewardMultiplier[msg.sender] = 1;
        return true;
    }

    /**
     * Increase reward multiplier based on holding time
     * 
     * The longer tokens are held, the higher the multiplier
     */
    function increaseRewardMultiplier() public returns (bool success) {
        require(lastRewardClaim[msg.sender] > 0, "Must register first");
        require(balanceOf[msg.sender] > 0, "Must hold tokens");
        
        // Vulnerable: Uses block.timestamp for multiplier calculation
        uint256 timeSinceLastClaim = now - lastRewardClaim[msg.sender];
        if (timeSinceLastClaim >= rewardCooldownPeriod) {
            rewardMultiplier[msg.sender] += 1;
            lastRewardClaim[msg.sender] = now;
        }
        return true;
    }

    /**
     * Claim time-based rewards
     * 
     * Rewards are calculated based on time elapsed and multiplier
     */
    function claimTimebasedReward() public returns (bool success) {
        require(lastRewardClaim[msg.sender] > 0, "Must register first");
        require(balanceOf[msg.sender] > 0, "Must hold tokens to claim rewards");
        
        // Vulnerable: Relies on block.timestamp for reward calculation
        uint256 timeSinceLastClaim = now - lastRewardClaim[msg.sender];
        require(timeSinceLastClaim >= rewardCooldownPeriod, "Cooldown period not met");
        
        // Calculate reward based on time and multiplier
        uint256 timeBonus = timeSinceLastClaim / rewardCooldownPeriod;
        uint256 rewardAmount = baseRewardAmount * rewardMultiplier[msg.sender] * timeBonus;
        
        // Mint new tokens as reward
        balanceOf[msg.sender] += rewardAmount;
        totalSupply += rewardAmount;
        
        // Update last claim time
        lastRewardClaim[msg.sender] = now;
        
        Transfer(0x0, msg.sender, rewardAmount);
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
