/*
 * ===== SmartInject Injection Details =====
 * Function      : claimReward
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
 * This injection adds a reward system with timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability manifests in the claimReward() function which relies on 'now' (block.timestamp) for cooldown calculations. A malicious miner can manipulate block timestamps within reasonable bounds to claim rewards earlier than intended. The exploitation requires: 1) First calling setRewardEligibility() to establish initial timestamp, 2) Waiting or manipulating timestamps, 3) Calling claimReward() multiple times with timestamp manipulation. The state (lastRewardTime, rewardAccumulator) persists between transactions, making this a stateful multi-transaction vulnerability.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for reward system
    mapping(address => uint256) lastRewardTime;
    mapping(address => uint256) rewardAccumulator;
    uint256 public rewardCooldown = 24 hours;
    uint256 public rewardRate = 100; // tokens per claim
    // === END STATE VARIABLES ===

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

    // === BEGIN VULNERABLE FUNCTIONS ===
    // Function with timestamp dependence vulnerability
    function claimReward() public returns (bool success) {
        // Vulnerable to timestamp manipulation - miners can influence when rewards are available
        require(now >= lastRewardTime[msg.sender] + rewardCooldown);

        // Update state that persists between transactions
        lastRewardTime[msg.sender] = now;
        rewardAccumulator[msg.sender] += rewardRate;

        // Mint new tokens as reward
        balanceOf[msg.sender] += rewardRate;
        totalSupply += rewardRate;

        Transfer(0x0, msg.sender, rewardRate);
        return true;
    }

    // Function to set reward eligibility - requires multiple transactions to exploit
    function setRewardEligibility() public {
        // This function sets initial eligibility timestamp
        if (lastRewardTime[msg.sender] == 0) {
            lastRewardTime[msg.sender] = now;
        }
    }

    // Function to check reward availability - depends on timestamp
    function getRewardAvailableTime(address user) public view returns (uint256) {
        if (lastRewardTime[user] == 0) {
            return now;
        }
        return lastRewardTime[user] + rewardCooldown;
    }
    // === END VULNERABLE FUNCTIONS ===

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
