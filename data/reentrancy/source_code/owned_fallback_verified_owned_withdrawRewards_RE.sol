/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability that requires multiple transactions to exploit. The attacker must first call distributeRewards() to accumulate pending rewards (state setup), then call withdrawRewards() with a malicious contract that re-enters the function during the external call. The vulnerability exists because the state update (pendingRewards[msg.sender] = 0) happens after the external call, allowing the attacker to drain rewards multiple times before the state is updated.
 */
pragma solidity >=0.4.22 <0.6.0;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}

contract DalyVenturesShares is owned {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;

    // Reward system state variables
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public lastRewardClaim;
    uint256 public rewardPool;
    bool public rewardSystemActive = false;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // Events for reward system
    event RewardDistributed(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 100000000 * 10 ** uint256(18);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
        name = "Daly Ventures Shares";                         // Set the name for display purposes
        symbol = "DVS";                                        // Set the symbol for display purposes
        // rewardSystemActive initialized above
    }

    /**
     * Activate reward system and fund initial pool
     */
    function activateRewardSystem() public {
        require(msg.sender == owner);
        require(!rewardSystemActive);
        rewardSystemActive = true;
        rewardPool = totalSupply / 100; // 1% of total supply as initial reward pool
    }

    /**
     * Distribute rewards to token holders based on their balance
     * This creates the first state that needs to be set up
     */
    function distributeRewards() public {
        require(rewardSystemActive);
        require(balanceOf[msg.sender] > 0);
        require(block.timestamp >= lastRewardClaim[msg.sender] + 86400); // 24 hours cooldown
        uint256 userBalance = balanceOf[msg.sender];
        uint256 rewardAmount = (userBalance * rewardPool) / totalSupply;
        if (rewardAmount > 0 && rewardPool >= rewardAmount) {
            pendingRewards[msg.sender] += rewardAmount;
            rewardPool -= rewardAmount;
            lastRewardClaim[msg.sender] = block.timestamp;
            emit RewardDistributed(msg.sender, rewardAmount);
        }
    }

    /**
     * Withdraw accumulated rewards - VULNERABLE TO REENTRANCY
     */
    function withdrawRewards() public {
        require(rewardSystemActive);
        require(pendingRewards[msg.sender] > 0);
        uint256 reward = pendingRewards[msg.sender];
        // VULNERABILITY: External call before state update
        // An attacker can create a malicious contract that calls back into withdrawRewards()
        // during the transfer, allowing them to drain rewards multiple times
        if (msg.sender.call.value(reward)("") ) {
            // State update happens AFTER external call - this is the vulnerability
            pendingRewards[msg.sender] = 0;
            emit RewardClaimed(msg.sender, reward);
        }
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != address(0x0));
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        emit Approval(msg.sender, _spender, _value);
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
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
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