/*
 * ===== SmartInject Injection Details =====
 * Function      : inflat
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based inflation bonuses. The vulnerability requires:
 * 
 * **Specific Changes Made:**
 * 1. Added state variables `lastInflationTime` and `inflationWindow` to track timing between inflation calls
 * 2. Implemented a 5-minute cooldown period between inflation calls using `block.timestamp`
 * 3. Created timestamp-dependent bonus multipliers that activate during specific time windows (10-15 minutes and 30-35 minutes after last inflation)
 * 4. Used `block.timestamp` directly for critical financial calculations without proper validation
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Contract creator calls `inflat()` for the first time, setting `lastInflationTime = block.timestamp`
 * 2. **Transaction 2**: Wait for the appropriate time window (10-15 minutes or 30-35 minutes later)
 * 3. **Transaction 3**: Malicious miner can manipulate `block.timestamp` within the ~15 second range they control to:
 *    - Ensure they hit the bonus multiplier windows exactly
 *    - Maximize the bonus by timing the block timestamp to fall within the 2x or 3x multiplier ranges
 *    - Repeat this process across multiple blocks to accumulate excessive inflation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction because `lastInflationTime` must be set in a previous transaction
 * - The state persistence between transactions is essential - the timing calculation depends on the previously stored `lastInflationTime`
 * - Multiple sequential transactions are needed to repeatedly exploit the timing windows
 * - The cooldown period forces separation between transactions, creating windows of opportunity for timestamp manipulation
 * 
 * **Exploitation Scenario:**
 * A malicious miner could:
 * 1. Call `inflat(1000)` initially (Transaction 1)
 * 2. Wait exactly 10 minutes, then mine a block with `block.timestamp` manipulated to be within the 600-900 second window
 * 3. Call `inflat(1000)` again, receiving 2000 tokens instead of 1000 (Transaction 2)
 * 4. Repeat this process to continuously exploit the 2x and 3x multiplier windows
 * 
 * This creates a realistic timestamp dependence vulnerability where miners can manipulate block timestamps to gain unfair advantages in token inflation, requiring multiple transactions and state accumulation to exploit effectively.
 */
pragma solidity ^0.4.16;
contract Token{
  uint256 public totalSupply;

  function balanceOf(address _owner) public constant returns (uint256 balance);
  function transfer(address _to, uint256 _value) public returns (bool success);
  function transferFrom(address _from, address _to, uint256 _value) public returns
  (bool success);

  function approve(address _spender, uint256 _value) public returns (bool success);

  function allowance(address _owner, address _spender) public constant returns
  (uint256 remaining);

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256
  _value);
  event Burn(address indexed from, uint256 value);
  event Inflat(address indexed from, uint256 value);

}

contract FeibeiContract is Token {


  uint8 constant public decimals = 18;
  string constant public name = "FeibeiContract";
  string constant public symbol = "FB";
  uint public totalSupply = 1000000000 * 10 ** uint256(decimals);
  address contract_creator;

  // Added state variables for inflation timing
  uint256 public lastInflationTime = 0;
  uint256 public inflationWindow = 0;

  // Changed to recommended constructor syntax
  constructor() public {
    balances[msg.sender] = totalSupply; 
    contract_creator=msg.sender;
    
  }
  
  function inflat(uint256 _value) public returns(bool success){
    require(msg.sender == contract_creator);
    require(_value > 0);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based inflation control with vulnerability
    if (lastInflationTime == 0) {
        // First inflation sets the baseline
        lastInflationTime = block.timestamp;
        inflationWindow = block.timestamp + 3600; // 1 hour window
    } else {
        require(block.timestamp >= lastInflationTime + 300); // 5 minute cooldown
        // Vulnerability: Timestamp-dependent bonus multiplier
        // Miners can manipulate block.timestamp within ~15 second range
        uint256 timeDiff = block.timestamp - lastInflationTime;
        uint256 bonusMultiplier = 1;
        // Critical flaw: Using block.timestamp for financial calculations
        if (timeDiff >= 600 && timeDiff <= 900) { // 10-15 minute window
            bonusMultiplier = 2; // Double inflation during this window
        } else if (timeDiff >= 1800 && timeDiff <= 2100) { // 30-35 minute window  
            bonusMultiplier = 3; // Triple inflation during this window
        }
        // Apply timestamp-dependent bonus
        _value = _value * bonusMultiplier;
        lastInflationTime = block.timestamp;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    totalSupply += _value;
    balances[contract_creator] +=_value;
    Inflat(contract_creator, _value);
    return true;
  }

  function transfer(address _to, uint256 _value) public returns (bool success) {
    require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
    require(_to != 0x0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    Transfer(msg.sender, _to, _value);
    return true;
  }

  function transferFrom(address _from, address _to, uint256 _value) public returns
  (bool success) {
    require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
    balances[_to] += _value;
    balances[_from] -= _value; 
    allowed[_from][msg.sender] -= _value;
    Transfer(_from, _to, _value);
    return true;
  }
  function balanceOf(address _owner) public constant returns (uint256 balance) {
    return balances[_owner];
  }

  function approve(address _spender, uint256 _value) public returns (bool success)
  {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }
  
  function burn(uint256 _value) public {
    require(_value > 0);
    require(_value <= balances[msg.sender]);
    address burner = msg.sender;
    balances[burner] -= _value;
    totalSupply -=_value;
    Burn(burner, _value);
  }
  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;
}
