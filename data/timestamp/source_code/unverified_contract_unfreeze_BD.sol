/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added State Variables** (assumed to exist in contract):
 *    - `freezeTimestamp[msg.sender]`: Records when user first attempted to unfreeze
 *    - `lastFreezeTime[msg.sender]`: Records when tokens were last frozen  
 *    - `totalPenalties[msg.sender]`: Accumulates penalties over time
 *    - `lastUnfreezeTime[msg.sender]`: Tracks last unfreeze timestamp
 * 
 * 2. **Time-Based Logic Using block.timestamp**:
 *    - Enforces 24-hour cooldown between freeze and unfreeze operations
 *    - Implements decreasing penalty system based on elapsed time
 *    - Uses block.timestamp for all time calculations without proper validation
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User freezes tokens (sets lastFreezeTime)
 *    - **Transaction 2**: User attempts unfreeze before 24h cooldown (fails, but sets freezeTimestamp)
 *    - **Transaction 3**: Miner manipulates block.timestamp to bypass cooldown and reduce penalties
 *    - **Transaction 4**: User unfreezes with manipulated timestamp benefits
 * 
 * 4. **Stateful Vulnerability Requirements**:
 *    - State must persist between transactions (freeze times, penalty accumulation)
 *    - Vulnerability only exploitable through sequence of operations
 *    - Each transaction builds upon previous state changes
 * 
 * 5. **Timestamp Manipulation Risks**:
 *    - Miners can manipulate block.timestamp within 15-second tolerance
 *    - Users can exploit timing windows between blocks
 *    - Time-based penalties can be gamed through timestamp manipulation
 *    - Sequential transactions enable accumulated exploitation of timing dependencies
 * 
 * The vulnerability is realistic and mirrors real-world patterns where time-based financial logic relies on manipulable block properties without proper validation or external time sources.
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
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
contract VS is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Add necessary mappings for freeze/unfreeze logic
    mapping (address => uint256) public freezeTimestamp;
    mapping (address => uint256) public lastFreezeTime;
    mapping (address => uint256) public totalPenalties;
    mapping (address => uint256) public lastUnfreezeTime;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function VS(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        lastFreezeTime[msg.sender] = block.timestamp; // Initialize lastFreezeTime
        return true;
    }
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based unfreezing with accumulated penalties
        uint256 currentTime = block.timestamp;
        uint256 freezeTime = freezeTimestamp[msg.sender];
        
        // If no freeze time recorded, set it to current time (first unfreeze attempt)
        if (freezeTime == 0) {
            freezeTimestamp[msg.sender] = currentTime;
            // Require minimum 24 hours between freeze and unfreeze
            if (currentTime < lastFreezeTime[msg.sender] + 86400) {
                throw; // Too early to unfreeze
            }
        }
        
        // Calculate time-based penalty - decreases over time
        uint256 timePassed = currentTime - freezeTime;
        uint256 penaltyRate = 100; // Start at 100% penalty
        
        // Penalty decreases by 10% every 12 hours, but using block.timestamp
        if (timePassed >= 43200) { // 12 hours
            penaltyRate = SafeMath.safeSub(penaltyRate, (timePassed / 43200) * 10);
        }
        
        // Minimum penalty of 5%
        if (penaltyRate < 5) {
            penaltyRate = 5;
        }
        
        // Apply penalty to unfrozen amount
        uint256 penalty = SafeMath.safeMul(_value, penaltyRate) / 100;
        uint256 actualUnfrozen = SafeMath.safeSub(_value, penalty);
        
        // Accumulate total penalties for this user
        totalPenalties[msg.sender] = SafeMath.safeAdd(totalPenalties[msg.sender], penalty);
        
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], actualUnfrozen);
        
        // Update last action timestamp for next calculation
        lastUnfreezeTime[msg.sender] = currentTime;
        
        Unfreeze(msg.sender, actualUnfrozen);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() payable {
    }
}
