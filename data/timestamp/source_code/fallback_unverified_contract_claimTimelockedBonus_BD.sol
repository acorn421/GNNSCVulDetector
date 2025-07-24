/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimelockedBonus
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
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction timelock bonus system. The vulnerability requires multiple transactions to exploit: 1) First, a user calls requestBonusTokens() to initiate a timelock claim, 2) State persists between transactions with bonusClaimTime and bonusAmount mappings, 3) Later, the user calls claimTimelockedBonus() which relies on 'now >= bonusClaimTime[msg.sender]' for validation. Malicious miners can manipulate block timestamps to either delay or accelerate the bonus claiming process, potentially allowing early claims or preventing legitimate claims. The vulnerability is stateful as it depends on persistent state variables (bonusClaimTime, bonusAmount) that maintain values across multiple transactions.
 */
pragma solidity ^0.4.24;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {
    /**
    * @dev Multiplies two numbers, reverts on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
    * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0); // Solidity only automatically asserts when dividing by 0
        uint256 c = a / b;
        return c;
    }

    /**
    * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
    * @dev Adds two numbers, reverts on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    /**
    * @dev Divides two numbers and returns the remainder (unsigned integer modulo),
    * reverts when dividing by zero.
    */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0);
        return a % b;
    }
}

contract ATMToken {
    using SafeMath for uint256;
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    // 8 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timelock bonus system - users can claim bonus tokens after a waiting period
    mapping (address => uint256) public bonusClaimTime;
    mapping (address => uint256) public bonusAmount;
    uint256 public bonusUnlockPeriod = 7 days;
    uint256 public totalBonusPool;

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        totalBonusPool = 1000000 * 10 ** uint256(decimals); // initialize totalBonusPool correctly
    }

    /**
     * Request bonus tokens with timelock
     * Users can request bonus tokens but must wait for the unlock period
     */
    function requestBonusTokens(uint256 _amount) public returns (bool) {
        require(_amount > 0);
        require(_amount <= totalBonusPool);
        require(bonusClaimTime[msg.sender] == 0); // No pending claims
        
        bonusClaimTime[msg.sender] = now + bonusUnlockPeriod;
        bonusAmount[msg.sender] = _amount;
        
        return true;
    }

    /**
     * Claim bonus tokens after timelock period
     * VULNERABILITY: Timestamp dependence allows miners to manipulate block timestamps
     * This is a multi-transaction vulnerability requiring:
     * 1. First transaction: requestBonusTokens() to set the timelock
     * 2. Wait for time period (state persists between transactions)
     * 3. Second transaction: claimTimelockedBonus() to claim tokens
     */
    function claimTimelockedBonus() public returns (bool) {
        require(bonusClaimTime[msg.sender] > 0); // Must have pending claim
        require(now >= bonusClaimTime[msg.sender]); // Vulnerable to timestamp manipulation
        require(bonusAmount[msg.sender] > 0);
        require(totalBonusPool >= bonusAmount[msg.sender]);
        
        uint256 claimAmount = bonusAmount[msg.sender];
        
        // Reset claim state
        bonusClaimTime[msg.sender] = 0;
        bonusAmount[msg.sender] = 0;
        
        // Transfer bonus tokens
        totalBonusPool = totalBonusPool.sub(claimAmount);
        balanceOf[msg.sender] = balanceOf[msg.sender].add(claimAmount);
        totalSupply = totalSupply.add(claimAmount);
        
        emit Transfer(address(0), msg.sender, claimAmount);
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint256 _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != address(0));
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to].add(_value) >= balanceOf[_to]);
        // Save this for an assertion in the future
        uint256 previousBalances = balanceOf[_from].add(balanceOf[_to]);
        // Subtract from the sender
        balanceOf[_from] = balanceOf[_from].sub(_value);
        // Add the same to the recipient
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
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
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
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
    function approve(address _spender, uint256 _value) public returns (bool) {
        require(_spender != address(0));
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
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
        returns (bool) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
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
    function burn(uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);            // Subtract from the sender
        totalSupply = totalSupply.sub(_value);                      // Updates totalSupply
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
    function burnFrom(address _from, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] = balanceOf[_from].sub(_value);                         // Subtract from the targeted balance
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);             // Subtract from the sender's allowance
        totalSupply = totalSupply.sub(_value);                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}