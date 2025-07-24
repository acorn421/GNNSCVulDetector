/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBasedBonus
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
 * This vulnerability introduces a timestamp dependence issue where users can manipulate the bonus claiming mechanism across multiple transactions. The vulnerability is stateful and multi-transaction because: 1) It requires setting up state through multiple bonus claims to build up a streak, 2) The vulnerability depends on the lastClaimTime state persisting between transactions, 3) An attacker needs to perform multiple transactions over time to maximize exploitation, 4) The 'now' timestamp can be manipulated by miners within a 15-second window, allowing attackers to potentially claim bonuses more frequently than intended by timing their transactions strategically across multiple blocks.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TokenERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TokenERC20(
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

/******************************************/
/*       ADVANCED TOKEN STARTS HERE       */
/******************************************/

contract ISLToken is TokenERC20 {

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Time-based bonus system state variables
    mapping (address => uint256) public lastClaimTime;
    mapping (address => uint256) public bonusStreak;
    uint256 public bonusRate = 100; // 100 tokens per day
    uint256 public streakMultiplier = 2; // 2x multiplier after 3 days
    uint256 public constant BONUS_INTERVAL = 1 days;
    uint256 public constant STREAK_THRESHOLD = 3;
    // === END OF VARIABLE DECLARATIONS ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ISLToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}

    /**
     * Claim daily bonus tokens based on time
     * 
     * Users can claim bonus tokens once per day, with streak multipliers
     * 
     * @return success true if bonus was claimed successfully
     */
    function claimTimeBasedBonus() public returns (bool success) {
        require(now >= lastClaimTime[msg.sender] + BONUS_INTERVAL, "Bonus not available yet");
        
        uint256 bonusAmount = bonusRate;
        
        // Check if user maintained streak (claimed within 2 days of last claim)
        if (lastClaimTime[msg.sender] != 0 && now <= lastClaimTime[msg.sender] + (2 * BONUS_INTERVAL)) {
            bonusStreak[msg.sender]++;
        } else {
            bonusStreak[msg.sender] = 1; // Reset streak
        }
        
        // Apply streak multiplier
        if (bonusStreak[msg.sender] >= STREAK_THRESHOLD) {
            bonusAmount = bonusAmount * streakMultiplier;
        }
        
        // Update last claim time to current block timestamp
        lastClaimTime[msg.sender] = now;
        
        // Mint bonus tokens
        totalSupply += bonusAmount;
        balanceOf[msg.sender] += bonusAmount;
        
        Transfer(0x0, msg.sender, bonusAmount);
        return true;
    }
    
    /**
     * Set bonus parameters (only for demonstration of multi-transaction vulnerability)
     * 
     * @param newRate new bonus rate per day
     * @param newMultiplier new streak multiplier
     */
    function setBonusParameters(uint256 newRate, uint256 newMultiplier) public {
        require(msg.sender == address(this), "Only contract can set parameters");
        bonusRate = newRate;
        streakMultiplier = newMultiplier;
    }
}