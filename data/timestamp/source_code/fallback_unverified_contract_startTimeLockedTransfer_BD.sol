/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeLockedTransfer
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
 * This vulnerability introduces timestamp dependence in a multi-transaction time-locked transfer system. The vulnerability is stateful and requires multiple transactions: 1) startTimeLockedTransfer() to create a locked transfer, 2) executeTimeLockedTransfer() to execute it after the time lock expires. The vulnerability allows miners to manipulate block.timestamp to either execute transfers early or prevent execution by manipulating the timestamp. The state persists between transactions through the timeLockedTransfers mapping, making this a classic stateful, multi-transaction vulnerability that requires accumulated state changes and a sequence of operations to exploit.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract QuantumBlock {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
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
    // State variables for time-locked transfers
    struct TimeLockedTransfer {
        address from;
        address to;
        uint256 amount;
        uint256 unlockTime;
        bool executed;
    }
    
    mapping (uint256 => TimeLockedTransfer) public timeLockedTransfers;
    uint256 public transferCounter = 0;
    
    // Events for time-locked transfers
    event TimeLockedTransferCreated(uint256 indexed transferId, address indexed from, address indexed to, uint256 amount, uint256 unlockTime);
    event TimeLockedTransferExecuted(uint256 indexed transferId, address indexed from, address indexed to, uint256 amount);
    
    /**
     * Start a time-locked transfer
     *
     * Creates a transfer that can only be executed after a certain time
     * VULNERABILITY: Uses block.timestamp which can be manipulated by miners
     *
     * @param _to The address of the recipient
     * @param _value The amount to transfer
     * @param _lockDuration Duration in seconds to lock the transfer
     */
    function startTimeLockedTransfer(address _to, uint256 _value, uint256 _lockDuration) public returns (uint256 transferId) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _value);
        require(_lockDuration > 0);
        
        // Lock the tokens immediately
        balanceOf[msg.sender] -= _value;
        
        transferId = transferCounter++;
        timeLockedTransfers[transferId] = TimeLockedTransfer({
            from: msg.sender,
            to: _to,
            amount: _value,
            unlockTime: block.timestamp + _lockDuration,  // VULNERABILITY: Timestamp dependence
            executed: false
        });
        
        TimeLockedTransferCreated(transferId, msg.sender, _to, _value, block.timestamp + _lockDuration);
        return transferId;
    }
    
    /**
     * Execute a time-locked transfer
     *
     * Executes a previously created time-locked transfer if the time has passed
     * VULNERABILITY: Relies on block.timestamp which miners can manipulate
     *
     * @param _transferId The ID of the transfer to execute
     */
    function executeTimeLockedTransfer(uint256 _transferId) public returns (bool success) {
        TimeLockedTransfer storage transfer = timeLockedTransfers[_transferId];
        
        require(transfer.from != 0x0);  // Transfer must exist
        require(!transfer.executed);    // Transfer must not be already executed
        require(block.timestamp >= transfer.unlockTime);  // VULNERABILITY: Timestamp dependence
        
        // Execute the transfer
        transfer.executed = true;
        balanceOf[transfer.to] += transfer.amount;
        
        TimeLockedTransferExecuted(_transferId, transfer.from, transfer.to, transfer.amount);
        Transfer(transfer.from, transfer.to, transfer.amount);
        
        return true;
    }
    
    /**
     * Cancel a time-locked transfer
     *
     * Allows the sender to cancel a time-locked transfer and get their tokens back
     * VULNERABILITY: Time check can be manipulated, allowing premature cancellation
     *
     * @param _transferId The ID of the transfer to cancel
     */
    function cancelTimeLockedTransfer(uint256 _transferId) public returns (bool success) {
        TimeLockedTransfer storage transfer = timeLockedTransfers[_transferId];
        
        require(transfer.from == msg.sender);  // Only sender can cancel
        require(!transfer.executed);           // Transfer must not be executed
        require(block.timestamp < transfer.unlockTime);  // VULNERABILITY: Can only cancel before unlock time
        
        // Return tokens to sender
        transfer.executed = true;  // Mark as executed to prevent double spending
        balanceOf[transfer.from] += transfer.amount;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function QuantumBlock(
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
