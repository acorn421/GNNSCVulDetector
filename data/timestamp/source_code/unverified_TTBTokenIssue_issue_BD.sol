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
 * Injected a stateful, multi-transaction timestamp dependence vulnerability that:
 * 
 * 1. **Specific Changes Made:**
 *    - Added `lastIssueTimestamp` mapping to track per-address issuance times
 *    - Added `issuanceCooldown` for time-based access control
 *    - Introduced `timeBasedMultiplier` that accumulates over time
 *    - Added `lastGlobalIssueTime` to track global timing state
 *    - Implemented timestamp-based cooldown checks
 *    - Added time-based multiplier logic that increases token issuance over time
 * 
 * 2. **Multi-Transaction Exploitation:**
 *    The vulnerability requires multiple transactions to exploit:
 *    
 *    **Transaction 1:** Initial issue call establishes baseline timestamps
 *    - Sets `lastIssueTimestamp[msg.sender]` and `lastGlobalIssueTime`
 *    - Issues tokens with `timeBasedMultiplier = 1`
 *    
 *    **Transaction 2:** Wait for cooldown period, then issue again
 *    - If more than 24 hours have passed, `timeBasedMultiplier` increases
 *    - Accumulated multiplier affects all future issuances
 *    
 *    **Transaction 3+:** Repeated exploitation
 *    - Each subsequent call after 24+ hours increases the multiplier
 *    - Miners can manipulate `block.timestamp` within ~15 minute tolerance
 *    - Attackers can coordinate timing to maximize multiplier accumulation
 * 
 * 3. **Why Multi-Transaction is Required:**
 *    - **State Accumulation:** The `timeBasedMultiplier` must be built up over multiple calls
 *    - **Cooldown Bypass:** Initial transaction sets baseline, subsequent ones exploit accumulated state
 *    - **Timestamp Manipulation:** Each transaction can slightly manipulate timestamps, but the real exploit comes from the accumulated effect across multiple calls
 *    - **Persistent State:** The vulnerability depends on stored timestamp values that persist between transactions and affect future behavior
 * 
 * 4. **Exploitation Scenario:**
 *    - Attacker waits for exactly 24 hours between calls to maximize multiplier growth
 *    - Miners can manipulate timestamps by up to 15 minutes to meet the 24-hour threshold earlier
 *    - Over time, `timeBasedMultiplier` grows exponentially, allowing massive token inflation
 *    - The vulnerability becomes more severe with each successful exploitation cycle
 * 
 * This creates a realistic timestamp dependence vulnerability where the damage accumulates over multiple transactions, making it impossible to exploit in a single atomic operation.
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
contract TTBTokenIssue {
    uint256 public lastYearTotalSupply = 15 * 10 ** 26; 
    uint8   public affectedCount = 0;
    bool    public initialYear = true; 
	address public tokenContractAddress;
    uint16  public preRate = 1000; 
    uint256 public lastBlockNumber;

    function TTBTokenIssue (address _tokenContractAddress) public{
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
        TTBToken tokenContract = TTBToken(tokenContractAddress);
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

contract TTBToken {
    string public name = 'Tip-Top Block';
    string public symbol = 'TTB';
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

    function TTBToken() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
        issueContractAddress = new TTBTokenIssue(address(this));
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastIssueTimestamp;
    uint256 public issuanceCooldown = 3600; // 1 hour cooldown
    uint256 public timeBasedMultiplier = 1;
    uint256 public lastGlobalIssueTime;

    function issue(uint256 amount) public {
        require(msg.sender == issueContractAddress);
        
        // Time-based access control with vulnerability
        if (lastIssueTimestamp[msg.sender] > 0) {
            require(block.timestamp > lastIssueTimestamp[msg.sender] + issuanceCooldown, "Cooldown period not met");
        }
        
        // Accumulate time-based multiplier using vulnerable timestamp logic
        if (lastGlobalIssueTime > 0) {
            uint256 timeDiff = block.timestamp - lastGlobalIssueTime;
            if (timeDiff > 86400) { // 24 hours
                timeBasedMultiplier = SafeOpt.add(timeBasedMultiplier, 1);
            }
        }
        
        // Apply time-based multiplier to amount (vulnerable to manipulation)
        uint256 adjustedAmount = SafeOpt.mul(amount, timeBasedMultiplier);
        
        balanceOf[owner] = SafeOpt.add(balanceOf[owner], adjustedAmount);
        totalSupply = SafeOpt.add(totalSupply, adjustedAmount);
        
        // Update timestamps for future checks
        lastIssueTimestamp[msg.sender] = block.timestamp;
        lastGlobalIssueTime = block.timestamp;
        
        Issue(adjustedAmount);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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