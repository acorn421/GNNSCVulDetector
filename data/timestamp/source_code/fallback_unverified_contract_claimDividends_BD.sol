/*
 * ===== SmartInject Injection Details =====
 * Function      : claimDividends
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
 * This vulnerability introduces a timestamp dependence issue in a dividend distribution system. The vulnerability is stateful and requires multiple transactions to exploit: 1) declareDividend() sets up the dividend pool and timestamp, 2) claimDividends() calculates rewards based on timestamp with early-claimer bonuses, 3) withdrawDividends() completes the process. Miners can manipulate block timestamps to claim higher bonuses by appearing to claim "early" even when they're not. The vulnerability requires state persistence across multiple transactions as the bonus calculation depends on the time difference between declaration and claiming, and the withdrawal requires a separate transaction after claiming.
 */
/**
 *Submitted for verification at Etherscan.io on 2018-06-04
*/

pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract UCCToken {
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
    // Dividend distribution variables
    uint256 public lastDividendTime;
    uint256 public dividendPool;
    mapping(address => uint256) public lastClaimTime;
    mapping(address => uint256) public pendingDividends;
    // === END DECLARATIONS FOR FALLBACK INJECTION ===

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function UCCToken(
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
     * Declare dividend distribution
     * Only callable by contract owner, sets up dividend pool
     */
    function declareDividend(uint256 _amount) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(block.timestamp >= lastDividendTime + 30 days); // 30 day minimum between dividends
        
        dividendPool = _amount;
        lastDividendTime = block.timestamp;
        
        // Calculate pending dividends for all holders based on current timestamp
        // This creates a time window where early claimers get advantages
        return true;
    }
    
    /**
     * Claim dividend rewards
     * Vulnerable to timestamp manipulation - early claims get better rates
     */
    function claimDividends() public returns (bool success) {
        require(dividendPool > 0);
        require(balanceOf[msg.sender] > 0);
        require(block.timestamp >= lastClaimTime[msg.sender] + 1 days); // 1 day cooldown
        
        // Time-sensitive calculation - earlier claims get bonus multiplier
        uint256 timeSinceDeclaration = block.timestamp - lastDividendTime;
        uint256 bonusMultiplier = 100;
        
        // Vulnerable: Miners can manipulate timestamp to get better bonuses
        if (timeSinceDeclaration <= 1 hours) {
            bonusMultiplier = 150; // 50% bonus for very early claims
        } else if (timeSinceDeclaration <= 6 hours) {
            bonusMultiplier = 125; // 25% bonus for early claims
        } else if (timeSinceDeclaration <= 24 hours) {
            bonusMultiplier = 110; // 10% bonus for day-one claims
        }
        
        // Calculate dividend based on token balance and time bonus
        uint256 userShare = (balanceOf[msg.sender] * dividendPool) / totalSupply;
        uint256 dividendAmount = (userShare * bonusMultiplier) / 100;
        
        // State changes that persist between transactions
        lastClaimTime[msg.sender] = block.timestamp;
        pendingDividends[msg.sender] += dividendAmount;
        
        return true;
    }
    
    /**
     * Withdraw claimed dividends
     * Second step in multi-transaction exploit
     */
    function withdrawDividends() public returns (bool success) {
        require(pendingDividends[msg.sender] > 0);
        require(block.timestamp >= lastClaimTime[msg.sender] + 2 hours); // 2 hour withdrawal delay
        
        uint256 amount = pendingDividends[msg.sender];
        pendingDividends[msg.sender] = 0;
        
        // Transfer dividend tokens (assumes contract has sufficient balance)
        require(balanceOf[address(this)] >= amount);
        balanceOf[address(this)] -= amount;
        balanceOf[msg.sender] += amount;
        
        emit Transfer(address(this), msg.sender, amount);
        return true;
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
