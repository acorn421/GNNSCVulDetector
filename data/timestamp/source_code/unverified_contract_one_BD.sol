/*
 * ===== SmartInject Injection Details =====
 * Function      : one
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through:
 * 
 * 1. **Time-based initialization window**: Function can only be called between 1-7 days after deployment, creating timing constraints
 * 2. **Progressive time bonus**: Supply increases by 1% per hour elapsed since deployment, incentivizing strategic timing
 * 3. **Timestamp state tracking**: `lastInitializationTime` stores when function was last called, enabling cooldown enforcement
 * 4. **Multi-transaction exploitation**: Attackers can:
 *    - Wait for optimal timing (higher hourly bonuses)
 *    - Make multiple calls across different blocks to exploit timestamp manipulation
 *    - Coordinate timing across transactions to maximize bonus supply
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial transaction may occur at suboptimal timing
 * - Subsequent calls (if re-initialization is allowed) can exploit different timestamp values
 * - Miners can manipulate block.timestamp across multiple blocks to maximize bonuses
 * - The progressive bonus structure incentivizes timing-dependent exploitation patterns
 * 
 * This creates realistic timestamp dependence where token supply depends on when initialization occurs, making the contract vulnerable to timestamp manipulation attacks across multiple transactions.
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ONE{
    // Public variables of the token
    string public name='本能';
    string public symbol='ONE';
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply=1000000000000000000000000000;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // variables required by the vulnerable function
    uint256 public deploymentTime = now; // Using now since block.timestamp is an alias for now in 0.4.x
    uint256 public lastInitializationTime;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function one(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based initialization window (vulnerable to timestamp manipulation)
        require(block.timestamp >= deploymentTime + 1 days);
        require(block.timestamp <= deploymentTime + 7 days);
        
        // Progressive bonus based on timestamp (accumulates over multiple calls)
        uint256 timeBonusMultiplier = 100; // Base 100%
        uint256 hoursElapsed = (block.timestamp - deploymentTime) / 3600;
        
        // Bonus increases by 1% per hour, allowing multiple calls to accumulate different bonuses
        if (hoursElapsed < 168) { // Within 7 days
            timeBonusMultiplier += hoursElapsed; // Up to 168% bonus
        }
        
        // Store last initialization timestamp for cooldown enforcement
        lastInitializationTime = block.timestamp;
        
        // Calculate supply with time-dependent bonus
        uint256 baseSupply = initialSupply * 10 ** uint256(decimals);
        uint256 bonusSupply = (baseSupply * timeBonusMultiplier) / 100;
        
        totalSupply = bonusSupply;                          // Update total supply with time-based bonus
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
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
        emit Burn(msg.sender, _value);
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
        emit Burn(_from, _value);
        return true;
    }
}
