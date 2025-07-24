/*
 * ===== SmartInject Injection Details =====
 * Function      : freezeAccount
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
 * This vulnerability introduces a stateful timestamp dependence issue that requires multiple transactions to exploit. The vulnerability works as follows:
 * 
 * 1. **First Transaction**: An attacker or legitimate user calls freezeAccount() which sets a freeze timestamp using block.timestamp + duration. This creates persistent state in the frozenUntil mapping.
 * 
 * 2. **State Persistence**: The freeze timestamp is stored in the contract's state and persists between transactions.
 * 
 * 3. **Second Transaction**: The attacker (if they are a miner or can influence mining) can manipulate the block.timestamp in subsequent transactions to bypass the freeze check in the modified transfer functions.
 * 
 * The vulnerability is stateful because:
 * - The frozenUntil mapping stores freeze timestamps that persist between transactions
 * - The freeze state affects future transfer operations
 * - Multiple function calls are required to set up and exploit the vulnerability
 * 
 * The timestamp manipulation can allow frozen accounts to transfer tokens when they shouldn't be able to, or prevent legitimate unfreezing when the time has passed.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract EX {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Mapping to track frozen accounts and their unlock timestamps
    mapping (address => uint256) public frozenUntil;
    // Event for freezing accounts
    event FrozenFunds(address target, uint256 unlockTime);

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function EX(
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
     * Freeze account for a specific duration
     *
     * Prevents an account from transferring tokens until a specific time
     * This function uses timestamp which can be manipulated by miners
     *
     * @param _target The address to freeze
     * @param _durationInSeconds Duration in seconds to freeze the account
     */
    function freezeAccount(address _target, uint256 _durationInSeconds) public {
        require(_target != 0x0);
        require(_durationInSeconds > 0);
        
        // VULNERABILITY: Using block.timestamp which can be manipulated by miners
        // This creates a stateful vulnerability that requires multiple transactions:
        // 1. First transaction: Call freezeAccount to set the freeze time
        // 2. State persists: frozenUntil mapping stores the unlock timestamp
        // 3. Second transaction: Attacker can manipulate block.timestamp to bypass freeze
        uint256 unlockTime = block.timestamp + _durationInSeconds;
        frozenUntil[_target] = unlockTime;
        
        emit FrozenFunds(_target, unlockTime);
    }

    /**
     * Check if account is currently frozen
     *
     * @param _account The address to check
     * @return true if account is frozen, false otherwise
     */
    function isFrozen(address _account) public view returns (bool) {
        // VULNERABILITY: Comparing stored timestamp with current block.timestamp
        // This comparison is vulnerable to timestamp manipulation
        return frozenUntil[_account] > block.timestamp;
    }

    /**
     * Unfreeze account immediately (emergency function)
     *
     * @param _target The address to unfreeze
     */
    function unfreezeAccount(address _target) public {
        require(_target != 0x0);
        frozenUntil[_target] = 0;
        emit FrozenFunds(_target, 0);
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
