/*
 * ===== SmartInject Injection Details =====
 * Function      : issue
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based bonus mechanics. The vulnerability involves:
 * 
 * 1. **State Variables Added**: 
 *    - `dailyBonusUsed` mapping to track which days bonuses were claimed
 *    - `lastIssueTimestamp` to track the last issuance time
 *    - `consecutiveBonusDays` to accumulate consecutive bonus days
 * 
 * 2. **Timestamp-Dependent Logic**: 
 *    - Daily bonus window (first hour of each day) determined by `block.timestamp % 86400 < 3600`
 *    - Consecutive day tracking using `block.timestamp / 86400` for day calculation
 *    - Bonus multiplier increases with consecutive days (up to 10x)
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls during bonus window to establish a streak
 *    - **Transaction 2+**: Attacker coordinates with miners to manipulate timestamps for subsequent days to maintain/extend streak
 *    - Each transaction builds state (`consecutiveBonusDays`) that enables larger bonuses in future transactions
 *    - The vulnerability requires multiple transactions over time to accumulate maximum bonus effect
 * 
 * 4. **Attack Vector**: 
 *    - Miners can manipulate `block.timestamp` within ~15 second tolerance
 *    - Attackers can coordinate with miners to ensure timestamps fall within bonus windows
 *    - State accumulation means early manipulation enables larger future exploitation
 *    - Multiple coordinated transactions can drain excessive tokens over time
 * 
 * The vulnerability preserves original functionality while adding realistic time-based features that create genuine security risks requiring stateful, multi-transaction exploitation.
 */
pragma solidity ^0.4.18;

library SafeOpt {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0); 
        uint256 c = a / b;
        assert(a == b * c);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a - b;
        assert(b <= a);
        assert(a == c + b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        assert(a == c - b);
        return c;
    }
}
contract TTDTokenIssue {
    uint256 public lastYearTotalSupply = 15 * 10 ** 26; 
    uint8   public affectedCount = 0;
    bool    public initialYear = true; 
	//uint16  public blockHeight = 2102400;
	address public tokenContractAddress;
    uint16  public preRate = 1000; 
    uint256 public lastBlockNumber;

    function TTDTokenIssue (address _tokenContractAddress) public{
        tokenContractAddress = _tokenContractAddress;
        lastBlockNumber = block.number;
    }

    function returnRate() internal returns (uint256){
        if(affectedCount == 10){
            if(preRate > 100){
                preRate -= 100;
            }
            affectedCount = 0;
        }
        return SafeOpt.div(preRate, 10);
    }

    function issue() public  {
        if(initialYear){
            require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
            initialYear = false;
        }
        require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
        TTDToken tokenContract = TTDToken(tokenContractAddress);
        if(affectedCount == 10){
            lastYearTotalSupply = tokenContract.totalSupply();
        }
        uint256 amount = SafeOpt.div(SafeOpt.mul(lastYearTotalSupply, returnRate()), 10000);
        require(amount > 0);
        tokenContract.issue(amount);
        lastBlockNumber = block.number;
        affectedCount += 1;
    }
}


interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

contract TTDToken {
    string public name = 'TTD Token';
    string public symbol = 'TTD';
    uint8 public decimals = 18;
    uint256 public totalSupply = 100 * 10 ** 26;

    address public issueContractAddress;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Issue(uint256 amount);

    function TTDToken() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
        issueContractAddress = new TTDTokenIssue(address(this));
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(uint256 => bool) public dailyBonusUsed;
    uint256 public lastIssueTimestamp;
    uint256 public consecutiveBonusDays;
    
    function issue(uint256 amount) public {
        require(msg.sender == issueContractAddress);
        
        // Store current timestamp for stateful tracking
        uint256 currentDay = block.timestamp / 86400; // Day number since epoch
        
        // Time-based bonus logic - vulnerable to timestamp manipulation
        if (block.timestamp % 86400 < 3600) { // First hour of each day
            if (!dailyBonusUsed[currentDay]) {
                // Mark bonus as used for this day
                dailyBonusUsed[currentDay] = true;
                
                // Check for consecutive days to build up bonus multiplier
                if (lastIssueTimestamp > 0 && currentDay == (lastIssueTimestamp / 86400) + 1) {
                    consecutiveBonusDays = SafeOpt.add(consecutiveBonusDays, 1);
                } else if (lastIssueTimestamp == 0 || currentDay > (lastIssueTimestamp / 86400) + 1) {
                    consecutiveBonusDays = 1; // Reset or start streak
                }
                
                // Apply cumulative bonus based on consecutive days (max 10x)
                uint256 bonusMultiplier = consecutiveBonusDays > 10 ? 10 : consecutiveBonusDays;
                amount = SafeOpt.add(amount, SafeOpt.div(SafeOpt.mul(amount, bonusMultiplier), 10));
            }
        }
        
        // Update state for next call
        lastIssueTimestamp = block.timestamp;
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balanceOf[owner] = SafeOpt.add(balanceOf[owner], amount);
        totalSupply = SafeOpt.add(totalSupply, amount);
        Issue(amount);
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balanceOf[_owner];
    }

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

    function transfer(address _to, uint256 _value) public returns (bool success){
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value <= balanceOf[msg.sender]);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function allowance(address _owner, address _spender) view public returns (uint256 remaining) {
        return allowance[_owner][_spender];
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