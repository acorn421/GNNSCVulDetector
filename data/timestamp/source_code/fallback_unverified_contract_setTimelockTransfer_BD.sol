/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimelockTransfer
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
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability. The vulnerability requires three separate transactions to exploit: 1) setTimelockTransfer to create a timelock with tokens locked, 2) wait for the timelock period while miners can manipulate timestamps, and 3) executeTimelockTransfer to claim tokens potentially earlier than intended. The vulnerability persists state between transactions through the timelock mappings, and miners can manipulate the 'now' timestamp within reasonable bounds (~900 seconds) to execute transfers earlier than intended, especially problematic for short timelocks.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract GoodBoyPoints {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 0;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Timelock state variables must be here, outside the constructor
    mapping (address => uint256) public timelockAmount;
    mapping (address => uint256) public timelockEndTime;
    mapping (address => address) public timelockRecipient;
    
    event TimelockSet(address indexed from, address indexed to, uint256 amount, uint256 unlockTime);
    event TimelockExecuted(address indexed from, address indexed to, uint256 amount);

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function GoodBoyPoints(
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
     * Set a timelock transfer that can be executed after a delay
     *
     * @param _to The address to transfer to after delay
     * @param _value The amount to transfer
     * @param _delay The delay in seconds before the transfer can be executed
     */
    function setTimelockTransfer(address _to, uint256 _value, uint256 _delay) public returns (bool success) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _value);
        require(_delay > 0);
        
        // Lock the tokens by reducing sender's balance
        balanceOf[msg.sender] -= _value;
        
        // Set timelock parameters - vulnerable to timestamp manipulation
        timelockAmount[msg.sender] = _value;
        timelockEndTime[msg.sender] = now + _delay;  // Vulnerable: 'now' can be manipulated by miners
        timelockRecipient[msg.sender] = _to;
        
        TimelockSet(msg.sender, _to, _value, timelockEndTime[msg.sender]);
        return true;
    }

    /**
     * Execute a previously set timelock transfer
     */
    function executeTimelockTransfer() public returns (bool success) {
        require(timelockAmount[msg.sender] > 0);
        require(timelockRecipient[msg.sender] != 0x0);
        // Vulnerable: Uses 'now' which can be manipulated by miners within certain bounds
        require(now >= timelockEndTime[msg.sender]);
        
        uint256 amount = timelockAmount[msg.sender];
        address recipient = timelockRecipient[msg.sender];
        
        // Clear timelock state
        timelockAmount[msg.sender] = 0;
        timelockEndTime[msg.sender] = 0;
        timelockRecipient[msg.sender] = 0x0;
        
        // Execute the transfer
        balanceOf[recipient] += amount;
        
        Transfer(msg.sender, recipient, amount);
        TimelockExecuted(msg.sender, recipient, amount);
        return true;
    }
    
    /**
     * Cancel a timelock transfer and reclaim tokens
     */
    function cancelTimelockTransfer() public returns (bool success) {
        require(timelockAmount[msg.sender] > 0);
        
        uint256 amount = timelockAmount[msg.sender];
        
        // Clear timelock state
        timelockAmount[msg.sender] = 0;
        timelockEndTime[msg.sender] = 0;
        timelockRecipient[msg.sender] = 0x0;
        
        // Return tokens to sender
        balanceOf[msg.sender] += amount;
        
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
