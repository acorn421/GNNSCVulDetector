/*
 * ===== SmartInject Injection Details =====
 * Function      : lock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability injection introduces a stateful, multi-transaction Timestamp Dependence vulnerability with the following components:
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables** (would need to be declared in contract):
 *    - `mapping(address => uint256) public lastLockTime` - Tracks last lock timestamp for each user
 *    - `mapping(address => uint256) public userLockDay` - Tracks current day for daily limit reset
 *    - `mapping(address => uint256) public dailyLockAmount` - Tracks daily lock amount per user
 *    - `uint256 public maxDailyLock = 1000000 * 10**18` - Maximum daily lock limit
 * 
 * 2. **Time-Based Bonus System**: Users receive bonus locked tokens based on time elapsed since their last lock operation, calculated using `block.timestamp`
 * 
 * 3. **Daily Lock Limits**: Daily lock limits reset based on `block.timestamp / 86400` (days since epoch)
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Time Bonus Manipulation**: 
 *    - Transaction 1: User calls `lock()` to establish `lastLockTime`
 *    - Time passes or miner manipulates timestamp
 *    - Transaction 2: User calls `lock()` again with manipulated timestamp to get excessive time bonus
 * 
 * 2. **Daily Limit Bypass**:
 *    - Transaction 1: User locks maximum daily amount
 *    - Transaction 2: Miner manipulates `block.timestamp` to appear as next day, resetting daily limit
 *    - Transaction 3: User locks additional amount beyond intended daily limit
 * 
 * 3. **Cross-Day Exploitation**:
 *    - Multiple transactions across manipulated day boundaries to bypass cumulative daily limits
 *    - Sequential lock operations with timestamp manipulation to gain unfair bonuses
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires establishing initial state (`lastLockTime`, `dailyLockAmount`) in one transaction before exploiting in subsequent transactions
 * 
 * 2. **Time-Dependent Logic**: The bonus calculation depends on time elapsed since previous lock operations, requiring at least two lock calls separated by time
 * 
 * 3. **Daily Limit Tracking**: The daily limit system requires multiple transactions to fully exploit - first to reach limit, then to bypass it through timestamp manipulation
 * 
 * 4. **Persistent State Dependencies**: Each transaction builds upon state from previous transactions, making single-transaction exploitation impossible
 * 
 * The vulnerability is realistic as time-based bonuses and daily limits are common in DeFi protocols, but the reliance on miner-manipulable `block.timestamp` creates exploitable conditions across multiple transactions.
 */
/*
**  CCT -- Community Credit Token
*/
pragma solidity ^0.4.11;

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }
  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }
  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }
  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract CCT is SafeMath{
    string public version = "1.0";
    string public name = "Community Credit Token";
    string public symbol = "CCT";
    uint8 public decimals = 18;
    uint256 public totalSupply = 5 * (10**9) * (10 **18);
	address public admin;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public lockOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // --- DECLARE missing state variables for lock functionality ---
    mapping(address => uint256) public lastLockTime;
    mapping(address => uint256) public userLockDay;
    mapping(address => uint256) public dailyLockAmount;
    uint256 public maxDailyLock = 1000000 * (10 ** 18); // or any default daily lock limit you want

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	/* This notifies clients about the amount frozen */
    event Lock(address indexed from, uint256 value);
	/* This notifies clients about the amount unfrozen */
    event Unlock(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CCT() public {
        admin = msg.sender;
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
    }
    /**
     * If we want to rebrand, we can.
     */
    function setName(string _name) public
    {
        if(msg.sender == admin)
            name = _name;
    }
    /**
     * If we want to rebrand, we can.
     */
    function setSymbol(string _symbol) public
    {
        if(msg.sender == admin)
            symbol = _symbol;
    }
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }
    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }
    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	function lock(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based lock bonus system - users get bonus locked tokens based on time elapsed
        uint256 timeBonus = 0;
        if (lastLockTime[msg.sender] > 0) {
            uint256 timeDiff = block.timestamp - lastLockTime[msg.sender];
            // Bonus calculation: 1% per day elapsed (86400 seconds)
            timeBonus = (_value * timeDiff) / 8640000; // Vulnerable to timestamp manipulation
        }
        
        // Daily lock limit resets based on block.timestamp
        uint256 currentDay = block.timestamp / 86400; // Days since epoch
        if (userLockDay[msg.sender] != currentDay) {
            userLockDay[msg.sender] = currentDay;
            dailyLockAmount[msg.sender] = 0;
        }
        
        uint256 totalLockAmount = _value + timeBonus;
        uint256 newDailyTotal = dailyLockAmount[msg.sender] + totalLockAmount;
        
        // Daily limit check (vulnerable to timestamp manipulation across days)
        if (newDailyTotal > maxDailyLock) throw;
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        lockOf[msg.sender] = SafeMath.safeAdd(lockOf[msg.sender], totalLockAmount);
        
        // Update tracking variables
        lastLockTime[msg.sender] = block.timestamp;
        dailyLockAmount[msg.sender] = newDailyTotal;
        
        Lock(msg.sender, totalLockAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return true;
    }
	function unlock(uint256 _value) public returns (bool success) {
        if (lockOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        lockOf[msg.sender] = SafeMath.safeSub(lockOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unlock(msg.sender, _value);
        return true;
    }
	// transfer balance to admin
	function withdrawEther(uint256 amount) public {
		if(msg.sender != admin) throw;
		admin.transfer(amount);
	}
	// can accept ether
	function() payable {
    }
}
