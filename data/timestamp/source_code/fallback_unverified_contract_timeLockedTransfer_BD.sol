/*
 * ===== SmartInject Injection Details =====
 * Function      : timeLockedTransfer
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
 * This injection adds time-locked transfer functionality that suffers from timestamp dependence vulnerability. The vulnerability is stateful and multi-transaction because: 1) First transaction creates a time lock using 'now' (block.timestamp), 2) State persists in the timeLocks mapping, 3) Second transaction attempts to execute the transfer by checking 'now' again. Miners can manipulate block timestamps within reasonable bounds (~15 seconds) to either delay or accelerate the execution of time-locked transfers, potentially front-running or preventing legitimate executions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract IMAGEWORLD {
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
    // Mapping to store time-locked transfers
    struct TimeLock {
        address from;
        address to;
        uint256 amount;
        uint256 unlockTime;
        bool executed;
        bool exists;
    }
    mapping(bytes32 => TimeLock) public timeLocks;
    
    event TimeLockedTransferCreated(bytes32 indexed lockId, address indexed from, address indexed to, uint256 amount, uint256 unlockTime);
    event TimeLockedTransferExecuted(bytes32 indexed lockId);
    
    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function IMAGEWORLD(
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
     * Create a time-locked transfer
     * 
     * @param _to The address of the recipient
     * @param _value The amount to transfer
     * @param _lockDuration Duration in seconds to lock the transfer
     */
    function createTimeLockedTransfer(address _to, uint256 _value, uint256 _lockDuration) public returns (bytes32) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _value);
        require(_lockDuration > 0);
        // Create unique lock ID based on sender, recipient, amount and current time
        bytes32 lockId = keccak256(abi.encodePacked(msg.sender, _to, _value, now));
        // Ensure lock doesn't already exist
        require(!timeLocks[lockId].exists);
        // Lock the tokens by transferring to this contract
        balanceOf[msg.sender] -= _value;
        // Create the time lock - VULNERABILITY: Uses 'now' (block.timestamp)
        timeLocks[lockId] = TimeLock({
            from: msg.sender,
            to: _to,
            amount: _value,
            unlockTime: now + _lockDuration,  // VULNERABLE: Miner can manipulate timestamp
            executed: false,
            exists: true
        });
        TimeLockedTransferCreated(lockId, msg.sender, _to, _value, now + _lockDuration);
        return lockId;
    }
    
    /**
     * Execute a time-locked transfer once the time period has elapsed
     * 
     * @param _lockId The ID of the time lock to execute
     */
    function executeTimeLockedTransfer(bytes32 _lockId) public returns (bool) {
        TimeLock storage lock = timeLocks[_lockId];
        require(lock.exists);
        require(!lock.executed);
        // VULNERABILITY: Uses 'now' for time comparison - miners can manipulate
        require(now >= lock.unlockTime);  // VULNERABLE: Timestamp dependence
        lock.executed = true;
        // Transfer tokens to recipient
        balanceOf[lock.to] += lock.amount;
        TimeLockedTransferExecuted(_lockId);
        Transfer(address(this), lock.to, lock.amount);
        return true;
    }
    
    /**
     * Check if a time-locked transfer is ready for execution
     * 
     * @param _lockId The ID of the time lock to check
     */
    function isTimeLockedTransferReady(bytes32 _lockId) public view returns (bool) {
        TimeLock storage lock = timeLocks[_lockId];
        if (!lock.exists || lock.executed) {
            return false;
        }
        // VULNERABILITY: Uses 'now' for time comparison
        return now >= lock.unlockTime;  // VULNERABLE: Timestamp dependence
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