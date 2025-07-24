/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimelockedBurn
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
 * This vulnerability introduces timestamp dependence through time-locked burn functionality. The vulnerability is stateful and multi-transaction because: 1) First transaction calls scheduleTimelockedBurn() to set up state (scheduledBurnAmount and scheduledBurnTime), 2) Second transaction calls executeTimelockedBurn() which relies on 'now' timestamp comparison. A malicious miner can manipulate block timestamps to either prevent execution when it should be allowed or allow execution before the intended time. The state persists between transactions in the mapping variables, making this a multi-transaction vulnerability that requires accumulated state changes.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract TRCTokenERC20 {
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked burn functionality
    mapping (address => uint256) public scheduledBurnAmount;
    mapping (address => uint256) public scheduledBurnTime;
    
    event BurnScheduled(address indexed account, uint256 amount, uint256 executeTime);
    event BurnExecuted(address indexed account, uint256 amount);
    
    /**
     * Schedule a time-locked burn of tokens
     * 
     * @param _amount The amount of tokens to burn
     * @param _delayMinutes The delay in minutes before the burn can be executed
     */
    function scheduleTimelockedBurn(uint256 _amount, uint256 _delayMinutes) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_delayMinutes > 0);
        
        // Cancel any existing scheduled burn
        scheduledBurnAmount[msg.sender] = _amount;
        scheduledBurnTime[msg.sender] = now + (_delayMinutes * 60);
        
        emit BurnScheduled(msg.sender, _amount, scheduledBurnTime[msg.sender]);
        return true;
    }
    
    /**
     * Execute a previously scheduled time-locked burn
     */
    function executeTimelockedBurn() public returns (bool success) {
        require(scheduledBurnAmount[msg.sender] > 0);
        require(now >= scheduledBurnTime[msg.sender]);
        require(balanceOf[msg.sender] >= scheduledBurnAmount[msg.sender]);
        
        uint256 burnAmount = scheduledBurnAmount[msg.sender];
        
        // Execute the burn
        balanceOf[msg.sender] -= burnAmount;
        totalSupply -= burnAmount;
        
        // Clear the scheduled burn
        scheduledBurnAmount[msg.sender] = 0;
        scheduledBurnTime[msg.sender] = 0;
        
        emit BurnExecuted(msg.sender, burnAmount);
        emit Burn(msg.sender, burnAmount);
        
        return true;
    }
    
    /**
     * Cancel a scheduled time-locked burn
     */
    function cancelTimelockedBurn() public returns (bool success) {
        require(scheduledBurnAmount[msg.sender] > 0);
        
        scheduledBurnAmount[msg.sender] = 0;
        scheduledBurnTime[msg.sender] = 0;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TRCTokenERC20(
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
