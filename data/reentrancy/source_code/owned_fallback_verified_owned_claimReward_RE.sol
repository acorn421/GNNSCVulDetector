/*
 * ===== SmartInject Injection Details =====
 * Function      : claimReward
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful reentrancy attack that requires multiple transactions to exploit. The attack flow is: 1) User stakes tokens to accumulate rewards, 2) User calls claimReward() which makes an external call before updating state, 3) During the external call, the attacker can call resetRewardClaim() to reset their claim status, 4) The attacker can then call claimReward() again in the same transaction or subsequent transactions. The vulnerability is stateful because it depends on the rewardBalance, rewardClaimed, and stakingBalance state variables persisting across multiple transactions, and requires the specific sequence of staking -> claiming -> resetting -> claiming again.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
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

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract DoosToken {
    string public name = 'DOOS';
    string public symbol = 'DOOS';
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Reentrancy ===
    // Reward system state variables (moved here to contract-level scope, removed visibility in mapping declaration for <0.5.0 syntax)
    mapping(address => uint256) rewardBalance;
    mapping(address => bool) rewardClaimed;
    mapping(address => uint256) stakingBalance;
    uint256 public totalRewardPool = 1000000 * 10 ** uint256(decimals);
    bool public rewardSystemActive = true;

    // Events
    event RewardClaimed(address indexed user, uint256 amount);
    event TokensStaked(address indexed user, uint256 amount);
    event TokensUnstaked(address indexed user, uint256 amount);

    function DoosToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    // Staking function to accumulate rewards over time
    function stakeTokens(uint256 _amount) public {
        require(_amount > 0, "Amount must be greater than 0");
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
        require(rewardSystemActive, "Reward system is not active");

        // Transfer tokens to contract (simulated staking)
        balanceOf[msg.sender] -= _amount;
        stakingBalance[msg.sender] += _amount;

        // Calculate reward (10% of staked amount)
        uint256 reward = _amount / 10;
        rewardBalance[msg.sender] += reward;

        TokensStaked(msg.sender, _amount);
    }

    // Vulnerable reward claiming function - STATEFUL REENTRANCY
    function claimReward() public {
        require(rewardSystemActive, "Reward system is not active");
        require(rewardBalance[msg.sender] > 0, "No rewards to claim");
        require(!rewardClaimed[msg.sender], "Reward already claimed");
        require(totalRewardPool >= rewardBalance[msg.sender], "Insufficient reward pool");

        uint256 reward = rewardBalance[msg.sender];

        // VULNERABILITY: External call before state update
        // This allows reentrancy in a multi-transaction scenario
        if (msg.sender.call.value(0)()) {
            // Simulate external contract interaction
        }

        // State updates happen after external call - VULNERABLE
        rewardClaimed[msg.sender] = true;
        totalRewardPool -= reward;
        balanceOf[msg.sender] += reward;

        RewardClaimed(msg.sender, reward);
    }

    // Function to unstake tokens
    function unstakeTokens(uint256 _amount) public {
        require(_amount > 0, "Amount must be greater than 0");
        require(stakingBalance[msg.sender] >= _amount, "Insufficient staking balance");

        stakingBalance[msg.sender] -= _amount;
        balanceOf[msg.sender] += _amount;

        TokensUnstaked(msg.sender, _amount);
    }

    // Reset reward claim status (creates vulnerability window)
    function resetRewardClaim() public {
        require(rewardSystemActive, "Reward system is not active");
        rewardClaimed[msg.sender] = false;
    }
    // === END FALLBACK INJECTION ===

    function _transfer(address _from, address _to, uint _value) internal {

        require(_to != 0x0);

        require(balanceOf[_from] >= _value);

        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;

        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
