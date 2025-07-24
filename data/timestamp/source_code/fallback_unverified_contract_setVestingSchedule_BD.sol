/*
 * ===== SmartInject Injection Details =====
 * Function      : setVestingSchedule
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a vesting system that requires multiple transactions to exploit. The vulnerability relies on miners' ability to manipulate block.timestamp within reasonable bounds (up to 900 seconds in the future). An attacker can exploit this by: 1) Setting up a vesting schedule, 2) Waiting for favorable timestamp conditions or mining blocks with manipulated timestamps, 3) Claiming tokens earlier than intended. The vulnerability is stateful as it depends on the vesting state persisting between the setVestingSchedule and claimVestedTokens transactions, and the exploitation requires multiple function calls over time.
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

contract GeneticHealthToken is TokenERC20 {

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Vesting schedule mapping
    mapping (address => uint256) public vestingStart;
    mapping (address => uint256) public vestingAmount;
    mapping (address => uint256) public vestingDuration;
    mapping (address => uint256) public vestedAmount;
    
    // Event for vesting schedule creation
    event VestingScheduleCreated(address indexed beneficiary, uint256 amount, uint256 duration);
    
    /**
     * Set vesting schedule for a beneficiary
     *
     * @param _beneficiary The address that will receive vested tokens
     * @param _amount The total amount to be vested
     * @param _duration The vesting duration in seconds
     */
    function setVestingSchedule(address _beneficiary, uint256 _amount, uint256 _duration) public {
        require(_beneficiary != 0x0);
        require(_amount > 0);
        require(_duration > 0);
        require(balanceOf[msg.sender] >= _amount);
        
        // Transfer tokens to contract for vesting
        balanceOf[msg.sender] -= _amount;
        
        // Set vesting parameters using block.timestamp
        vestingStart[_beneficiary] = block.timestamp;
        vestingAmount[_beneficiary] = _amount;
        vestingDuration[_beneficiary] = _duration;
        vestedAmount[_beneficiary] = 0;
        
        VestingScheduleCreated(_beneficiary, _amount, _duration);
    }
    
    /**
     * Claim vested tokens
     *
     * Allows beneficiary to claim tokens based on time elapsed
     */
    function claimVestedTokens() public {
        require(vestingAmount[msg.sender] > 0);
        require(block.timestamp >= vestingStart[msg.sender]);
        
        uint256 timeElapsed = block.timestamp - vestingStart[msg.sender];
        uint256 vestedTokens;
        
        if (timeElapsed >= vestingDuration[msg.sender]) {
            // Full vesting period has passed
            vestedTokens = vestingAmount[msg.sender];
        } else {
            // Partial vesting based on time elapsed
            vestedTokens = (vestingAmount[msg.sender] * timeElapsed) / vestingDuration[msg.sender];
        }
        
        uint256 claimableTokens = vestedTokens - vestedAmount[msg.sender];
        require(claimableTokens > 0);
        
        vestedAmount[msg.sender] += claimableTokens;
        balanceOf[msg.sender] += claimableTokens;
        
        Transfer(this, msg.sender, claimableTokens);
    }
    
    /**
     * Get claimable vested tokens for an address
     *
     * @param _beneficiary The address to check
     * @return The amount of tokens that can be claimed
     */
    function getClaimableTokens(address _beneficiary) public view returns (uint256) {
        if (vestingAmount[_beneficiary] == 0) {
            return 0;
        }
        
        uint256 timeElapsed = block.timestamp - vestingStart[_beneficiary];
        uint256 vestedTokens;
        
        if (timeElapsed >= vestingDuration[_beneficiary]) {
            vestedTokens = vestingAmount[_beneficiary];
        } else {
            vestedTokens = (vestingAmount[_beneficiary] * timeElapsed) / vestingDuration[_beneficiary];
        }
        
        return vestedTokens - vestedAmount[_beneficiary];
    }
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function GeneticHealthToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}
}
