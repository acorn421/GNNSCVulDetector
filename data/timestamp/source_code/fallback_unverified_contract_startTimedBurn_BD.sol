/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedBurn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability. Users can schedule token burns with time delays, but the execution relies on block.timestamp which can be manipulated by miners. The vulnerability requires multiple transactions: (1) startTimedBurn to schedule, (2) executeTimedBurn to execute, and potentially (3) cancelTimedBurn to manipulate timing. The state persists between transactions through scheduledBurnAmount and burnScheduleTime mappings. Miners can manipulate timestamps within bounds to either delay or accelerate burn execution, and users can cancel/reschedule burns to game the timing system.
 */
pragma solidity ^0.4.18;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
}
contract BEB is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to track scheduled burns
    mapping (address => uint256) public scheduledBurnAmount;
    mapping (address => uint256) public burnScheduleTime;
    // === END FALLBACK INJECTION ===

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    event BurnScheduled(address indexed user, uint256 amount, uint256 executeAfter);
    event TimedBurnExecuted(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BEB(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol,
        address holder
        )  public{
        balanceOf[holder] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = holder;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /* Schedule a token burn to execute after a specific time delay */
    function startTimedBurn(uint256 _value, uint256 _delayHours) public returns (bool success) {
        require(_value > 0);
        require(_delayHours > 0 && _delayHours <= 8760); // Max 1 year
        require(balanceOf[msg.sender] >= _value);
        require(scheduledBurnAmount[msg.sender] == 0); // No existing scheduled burn
        
        // Lock the tokens by moving them to a scheduled burn state
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        scheduledBurnAmount[msg.sender] = _value;
        
        // Set execution time - VULNERABLE: Uses block.timestamp which can be manipulated
        burnScheduleTime[msg.sender] = block.timestamp + (_delayHours * 3600);
        
        BurnScheduled(msg.sender, _value, burnScheduleTime[msg.sender]);
        return true;
    }
    
    /* Execute the scheduled burn if enough time has passed */
    function executeTimedBurn() public returns (bool success) {
        require(scheduledBurnAmount[msg.sender] > 0);
        
        // VULNERABLE: Timestamp dependence - miners can manipulate block.timestamp
        // This allows potential manipulation of when burns can be executed
        require(block.timestamp >= burnScheduleTime[msg.sender]);
        
        uint256 burnAmount = scheduledBurnAmount[msg.sender];
        
        // Clear the scheduled burn
        scheduledBurnAmount[msg.sender] = 0;
        burnScheduleTime[msg.sender] = 0;
        
        // Execute the burn
        totalSupply = SafeMath.safeSub(totalSupply, burnAmount);
        
        TimedBurnExecuted(msg.sender, burnAmount);
        Burn(msg.sender, burnAmount);
        return true;
    }
    
    /* Cancel a scheduled burn and return tokens to balance */
    function cancelTimedBurn() public returns (bool success) {
        require(scheduledBurnAmount[msg.sender] > 0);
        
        // VULNERABLE: No time restriction on cancellation allows manipulation
        // Users can cancel and reschedule to game timestamp-dependent logic
        uint256 returnAmount = scheduledBurnAmount[msg.sender];
        
        scheduledBurnAmount[msg.sender] = 0;
        burnScheduleTime[msg.sender] = 0;
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], returnAmount);
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        require(_to != 0x0);  // Prevent transfer to 0x0 address. Use burn() instead
		require(_value > 0); 
        require(balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		require(_value > 0); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
		require(_value > 0); 
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }

	// can accept ether
	function() payable public{
    }
}
