/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeBasedTransfer
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
 * This vulnerability introduces timestamp dependence across multiple transactions. The vulnerability requires: 1) First transaction to call startTimeBasedTransfer() which locks tokens and sets a release time based on 'now' timestamp, 2) Second transaction to call executeTimeBasedTransfer() which checks if 'now' >= releaseTime. Miners can manipulate timestamps to either delay or accelerate the execution of transfers, potentially causing tokens to be released earlier or later than intended. The vulnerability is stateful as it depends on the TimedTransfer struct state persisting between transactions.
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

contract LABEEToken is TokenERC20 {

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // State variables for time-based transfers
    struct TimedTransfer {
        address from;
        address to;
        uint256 amount;
        uint256 releaseTime;
        bool executed;
    }
    
    mapping(uint256 => TimedTransfer) public timedTransfers;
    uint256 public transferCounter = 0;
    
    /**
     * Start a time-based transfer that will be executed later
     * Creates a pending transfer that can be executed after the release time
     */
    function startTimeBasedTransfer(address _to, uint256 _amount, uint256 _delayInSeconds) public returns (uint256) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _amount);
        require(_delayInSeconds > 0);
        
        // Calculate release time using current timestamp
        uint256 releaseTime = now + _delayInSeconds;
        
        transferCounter++;
        timedTransfers[transferCounter] = TimedTransfer({
            from: msg.sender,
            to: _to,
            amount: _amount,
            releaseTime: releaseTime,
            executed: false
        });
        
        // Lock the tokens by reducing balance temporarily
        balanceOf[msg.sender] -= _amount;
        
        return transferCounter;
    }
    
    /**
     * Execute a previously started time-based transfer
     * Can only be called after the release time has passed
     */
    function executeTimeBasedTransfer(uint256 _transferId) public returns (bool) {
        TimedTransfer storage transfer = timedTransfers[_transferId];
        
        require(transfer.from != 0x0);
        require(!transfer.executed);
        
        // Vulnerable timestamp dependence - miners can manipulate this
        require(now >= transfer.releaseTime);
        
        transfer.executed = true;
        balanceOf[transfer.to] += transfer.amount;
        
        Transfer(transfer.from, transfer.to, transfer.amount);
        return true;
    }
    
    /**
     * Cancel a time-based transfer and return tokens to sender
     * Can only be called by the original sender
     */
    function cancelTimeBasedTransfer(uint256 _transferId) public returns (bool) {
        TimedTransfer storage transfer = timedTransfers[_transferId];
        
        require(transfer.from == msg.sender);
        require(!transfer.executed);
        
        transfer.executed = true;
        balanceOf[transfer.from] += transfer.amount;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function LABEEToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}
}
