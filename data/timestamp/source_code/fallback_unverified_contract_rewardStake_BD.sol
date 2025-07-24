/*
 * ===== SmartInject Injection Details =====
 * Function      : rewardStake
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence attack in the staking reward system. An attacker can exploit this by: 1) First calling stakeTokens() to begin staking, 2) Waiting or manipulating block timestamps, 3) Calling claimStakingRewards() multiple times with manipulated timestamps to claim inflated rewards. The vulnerability is stateful because it depends on the stakeStartTime and lastRewardClaim mappings that persist between transactions, and requires multiple function calls across different transactions to exploit effectively.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WenWanCoin {
    /* Public variables of the token */
    string public standard = 'WenWanCoin 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    /* Staking reward system - users can claim rewards based on how long they've staked */
    mapping (address => uint256) stakeBalance;
    mapping (address => uint256) stakeStartTime;
    mapping (address => uint256) lastRewardClaim;
    uint256 public rewardRate = 5; // 5% per day
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function WenWanCoin() {
        balanceOf[msg.sender] = 50000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 50000000 * 1000000000000000000;                        // Update total supply
        name = "WenWanCoin";                                   // Set the name for display purposes
        symbol = "WWC";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Stake tokens for rewards */
    function stakeTokens(uint256 _amount) returns (bool success) {
        if (balanceOf[msg.sender] < _amount) throw;
        if (_amount == 0) throw;
        
        balanceOf[msg.sender] -= _amount;
        stakeBalance[msg.sender] += _amount;
        
        // If first time staking, set start time
        if (stakeStartTime[msg.sender] == 0) {
            stakeStartTime[msg.sender] = now;
        }
        
        lastRewardClaim[msg.sender] = now;
        return true;
    }
    
    /* Claim staking rewards - vulnerable to timestamp manipulation */
    function claimStakingRewards() returns (bool success) {
        if (stakeBalance[msg.sender] == 0) throw;
        if (lastRewardClaim[msg.sender] == 0) throw;
        
        // Calculate time since last claim
        uint256 timeSinceLastClaim = now - lastRewardClaim[msg.sender];
        
        // Calculate reward based on time staked (vulnerable to timestamp manipulation)
        uint256 rewardAmount = (stakeBalance[msg.sender] * rewardRate * timeSinceLastClaim) / (100 * 1 days);
        
        // Update last claim time
        lastRewardClaim[msg.sender] = now;
        
        // Mint new tokens as reward
        balanceOf[msg.sender] += rewardAmount;
        totalSupply += rewardAmount;
        
        Transfer(0x0, msg.sender, rewardAmount);
        return true;
    }
    
    /* Unstake tokens */
    function unstakeTokens(uint256 _amount) returns (bool success) {
        if (stakeBalance[msg.sender] < _amount) throw;
        
        stakeBalance[msg.sender] -= _amount;
        balanceOf[msg.sender] += _amount;
        
        // Reset staking time if fully unstaked
        if (stakeBalance[msg.sender] == 0) {
            stakeStartTime[msg.sender] = 0;
            lastRewardClaim[msg.sender] = 0;
        }
        
        return true;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
