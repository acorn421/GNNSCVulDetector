/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBasedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a time-based reward system. The vulnerability is stateful and multi-transaction because: 1) It requires users to first call the function to establish a lastClaimTime, 2) Then wait for time to pass, 3) Then call again to claim rewards. The vulnerability allows miners to manipulate block timestamps to either accelerate reward claiming or prevent legitimate claims. The rewardAccumulator state persists between transactions and can be exploited over multiple calls by manipulating timestamps in subsequent blocks.
 */
pragma solidity ^0.4.16;    // Versão Compilador v0.4.16+commit.d7661dd9 - Runs (Optimiser):200 - Optimization Enabled: No // Dev Bth.Solutions
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract Zaigar {
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These mappings must be declared at contract level, not in constructor or inside functions
    mapping (address => uint256) lastClaimTime;
    mapping (address => uint256) rewardAccumulator;
    uint256 public rewardPerDay = 1000 * 10 ** 8; // 1000 tokens per day
    uint256 public constant SECONDS_PER_DAY = 86400;
    // === END DECLARATION ===

    function Zaigar() public {
        totalSupply = 1000000000 * 10 ** 8;
        balanceOf[msg.sender] = totalSupply;
        name = "Zaigar";
        symbol = "ZAI";
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function claimTimeBasedReward() public returns (bool success) {
        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastClaim = currentTime - lastClaimTime[msg.sender];
        // Allow claiming if at least 1 day has passed
        if (timeSinceLastClaim >= SECONDS_PER_DAY) {
            uint256 daysElapsed = timeSinceLastClaim / SECONDS_PER_DAY;
            uint256 reward = daysElapsed * rewardPerDay;
            // Accumulate reward for potential future claims
            rewardAccumulator[msg.sender] += reward;
            // Update last claim time
            lastClaimTime[msg.sender] = currentTime;
            // Mint new tokens as reward
            totalSupply += reward;
            balanceOf[msg.sender] += reward;
            Transfer(0x0, msg.sender, reward);
            return true;
        }
        return false;
    }

    function getPendingReward(address _user) public view returns (uint256) {
        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastClaim = currentTime - lastClaimTime[_user];
        if (timeSinceLastClaim >= SECONDS_PER_DAY) {
            uint256 daysElapsed = timeSinceLastClaim / SECONDS_PER_DAY;
            return daysElapsed * rewardPerDay;
        }
        return 0;
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
