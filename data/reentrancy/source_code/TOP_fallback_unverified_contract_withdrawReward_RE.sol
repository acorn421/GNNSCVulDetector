/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawReward
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability in reward withdrawal system. The vulnerability requires: 1) First transaction to call addReward() to set up state, 2) Second transaction to call withdrawReward() which makes external call before updating state, 3) Attacker's contract can reenter withdrawReward() during the external call to drain rewards. The rewardWithdrawInProgress flag provides some protection but can be bypassed through reentrancy timing. This creates a stateful vulnerability that persists across multiple transactions and requires accumulated reward balance to exploit.
 */
pragma solidity >=0.4.22 <0.6.0;

interface tokenRecipient { 
 function receiveApproval(address _from, uint256 _value, address _token, bytes memory _extraData) external; 
}

contract TOP {
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
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Reentrancy ===
    // State variables for reward system
    mapping(address => uint256) public rewardBalance;
    mapping(address => bool) public rewardWithdrawInProgress;
    uint256 public totalRewardPool;
    
    // Event for reward withdrawal
    event RewardWithdrawn(address indexed user, uint256 amount);
    
    /**
     * Add reward to user's balance
     * 
     * @param _user The address to add reward to
     * @param _amount The amount of reward to add
     */
    function addReward(address _user, uint256 _amount) public {
        require(_user != address(0x0), "Invalid address");
        require(_amount > 0, "Amount must be positive");
        
        rewardBalance[_user] += _amount;
        totalRewardPool += _amount;
    }
    
    /**
     * Withdraw accumulated rewards
     * 
     * This function is vulnerable to reentrancy attack requiring multiple transactions:
     * 1. First transaction: Call withdrawReward() to initiate withdrawal
     * 2. During external call: Attacker's contract calls back to withdrawReward()
     * 3. State is not properly updated until after external call completes
     */
    function withdrawReward() public {
        uint256 reward = rewardBalance[msg.sender];
        require(reward > 0, "No reward to withdraw");
        require(!rewardWithdrawInProgress[msg.sender], "Withdrawal already in progress");
        
        // Set withdrawal in progress flag
        rewardWithdrawInProgress[msg.sender] = true;
        
        // VULNERABILITY: External call before state update
        // This allows reentrancy if the recipient is a contract
        (bool success, ) = msg.sender.call.value(reward)("");
        require(success, "Transfer failed");
        
        // State update happens AFTER external call - this is the vulnerability
        rewardBalance[msg.sender] = 0;
        totalRewardPool -= reward;
        rewardWithdrawInProgress[msg.sender] = false;
        
        emit RewardWithdrawn(msg.sender, reward);
    }
    
    /**
     * Get reward balance for a user
     * 
     * @param _user The address to check
     * @return The reward balance
     */
    function getRewardBalance(address _user) public view returns (uint256) {
        return rewardBalance[_user];
    }
    // === END FALLBACK INJECTION ===

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string memory tokenName,
        string memory tokenSymbol
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
        require(_to != address(0x0));
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
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

// 'toptobit' token contract
//
// Symbol      : TOP
// Name        : TOP
// Total supply: 5000000000
// Decimals    : 18
//
// Copyright 2019 toptobit Inc. All rights reserved.

