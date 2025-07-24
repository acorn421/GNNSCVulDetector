/*
 * ===== SmartInject Injection Details =====
 * Function      : activateTimedTransfer
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
 * This vulnerability introduces timestamp dependence in a multi-transaction stateful context. The vulnerability requires two transactions: 1) activateTimedTransfer() to set up a delayed transfer, and 2) executeTimedTransfer() to execute it. The vulnerability lies in the reliance on 'now' (block.timestamp) for timing decisions. Miners can manipulate timestamps within reasonable bounds (typically 15 seconds), allowing them to either prevent execution by setting timestamps slightly behind the deadline or force early execution by setting timestamps ahead. The state persists between transactions through the mapping variables, making this a stateful vulnerability that requires multiple function calls to exploit.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract TokenHunter {
    // Public variables of the token
    string public name = 'TokenHunter';
    string public symbol = 'HR';
    uint8 public decimals = 4;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply = 210000000;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timed transfers
    mapping (address => uint256) public timedTransferAmount;
    mapping (address => address) public timedTransferTo;
    mapping (address => uint256) public timedTransferDeadline;
    mapping (address => bool) public timedTransferActive;
    // === END FALLBACK INJECTION ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TokenHunter(
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
     * Activate a timed transfer
     *
     * Sets up a transfer that can be executed after a specific time
     *
     * @param _to The address to transfer to
     * @param _value The amount to transfer
     * @param _delay Delay in seconds from now
     */
    function activateTimedTransfer(address _to, uint256 _value, uint256 _delay) public returns (bool success) {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(_delay > 0);
        
        timedTransferAmount[msg.sender] = _value;
        timedTransferTo[msg.sender] = _to;
        timedTransferDeadline[msg.sender] = now + _delay;
        timedTransferActive[msg.sender] = true;
        
        return true;
    }
    
    /**
     * Execute a previously activated timed transfer
     *
     * Executes the transfer if the time requirement is met
     */
    function executeTimedTransfer() public returns (bool success) {
        require(timedTransferActive[msg.sender]);
        require(now >= timedTransferDeadline[msg.sender]);
        require(balanceOf[msg.sender] >= timedTransferAmount[msg.sender]);
        
        address to = timedTransferTo[msg.sender];
        uint256 value = timedTransferAmount[msg.sender];
        
        // Clear the timed transfer state
        timedTransferActive[msg.sender] = false;
        timedTransferAmount[msg.sender] = 0;
        timedTransferTo[msg.sender] = 0x0;
        timedTransferDeadline[msg.sender] = 0;
        
        // Execute the transfer
        _transfer(msg.sender, to, value);
        
        return true;
    }
    
    /**
     * Check if timed transfer is ready for execution
     *
     * @param _user The address to check
     */
    function isTimedTransferReady(address _user) public view returns (bool) {
        return timedTransferActive[_user] && now >= timedTransferDeadline[_user];
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
