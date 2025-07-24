/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedMint
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
 * This vulnerability introduces timestamp dependence in a multi-transaction minting system. The vulnerability requires multiple steps to exploit: 1) First transaction calls enableTimedMint() to set up minting parameters, 2) Second transaction calls mintTokens() during the time window, 3) Optional third transaction calls extendMintingPeriod() to extend the window. A malicious miner can manipulate timestamps to extend minting periods, mint tokens outside intended windows, or bypass time-based restrictions. The vulnerability is stateful because it depends on persistent state variables (mintingStartTime, mintingEndTime, currentMintedAmount) that are modified across multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract ELYTE {
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
    // Timed minting functionality
    uint256 public mintingStartTime;
    uint256 public mintingEndTime;
    uint256 public maxMintAmount;
    uint256 public currentMintedAmount;
    bool public mintingEnabled;
    // === END FALLBACK INJECTION ===

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function ELYTE(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Enable timed minting with specific parameters
     * Only available for a limited time window
     */
    function enableTimedMint(uint256 _duration, uint256 _maxAmount) public {
        require(msg.sender == address(this) || balanceOf[msg.sender] > 0); // Basic auth check
        mintingStartTime = now;
        mintingEndTime = now + _duration;
        maxMintAmount = _maxAmount;
        currentMintedAmount = 0;
        mintingEnabled = true;
    }
    /**
     * Mint tokens during the allowed time window
     * Vulnerable to timestamp manipulation attacks
     */
    function mintTokens(uint256 _amount) public {
        require(mintingEnabled);
        require(now >= mintingStartTime && now <= mintingEndTime); // Timestamp dependence
        require(currentMintedAmount + _amount <= maxMintAmount);
        currentMintedAmount += _amount;
        totalSupply += _amount;
        balanceOf[msg.sender] += _amount;
        Transfer(0x0, msg.sender, _amount);
    }
    /**
     * Extend minting period - vulnerable to timestamp manipulation
     * Requires multiple transactions to exploit effectively
     */
    function extendMintingPeriod(uint256 _additionalTime) public {
        require(mintingEnabled);
        require(now <= mintingEndTime); // Check current time
        require(balanceOf[msg.sender] >= 1000); // Must hold tokens
        mintingEndTime += _additionalTime;
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
}
