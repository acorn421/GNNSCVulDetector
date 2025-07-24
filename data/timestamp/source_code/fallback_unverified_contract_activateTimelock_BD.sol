/*
 * ===== SmartInject Injection Details =====
 * Function      : activateTimelock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction timelock system. The vulnerability requires: 1) First transaction to activate the timelock with activateTimelock(), 2) Wait period where state persists, 3) Second transaction to release tokens with releaseTimelock(). The vulnerability lies in the reliance on block.timestamp (now) for time comparisons, which can be manipulated by miners within certain bounds (typically 15 seconds). A malicious miner could potentially manipulate the timestamp to bypass the timelock duration or cause unexpected behavior in time-dependent operations.
 */
pragma solidity ^0.4.12;

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
contract HZ is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timelock system for token releases
    uint256 public timelockDuration = 86400; // 24 hours in seconds
    mapping (address => uint256) public timelockActivated;
    mapping (address => uint256) public timelockAmount;
    
    event TimelockActivated(address indexed user, uint256 amount, uint256 unlockTime);
    event TimelockReleased(address indexed user, uint256 amount);
    
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function HZ() {
        balanceOf[msg.sender] = 50000000000;              // Give the creator all initial tokens
        totalSupply = 50000000000;                        // Update total supply
        name = 'Hertz';                                   // Set the name for display purposes
        symbol = 'HZ';                               // Set the symbol for display purposes
        decimals = 4;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }
    
    // Activate timelock for token release
    function activateTimelock(uint256 _amount) returns (bool success) {
        if (_amount <= 0) throw;
        if (balanceOf[msg.sender] < _amount) throw;
        
        // Transfer tokens to timelock
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
        timelockAmount[msg.sender] = SafeMath.safeAdd(timelockAmount[msg.sender], _amount);
        
        // Set unlock time based on current block timestamp
        timelockActivated[msg.sender] = now + timelockDuration;
        
        TimelockActivated(msg.sender, _amount, timelockActivated[msg.sender]);
        return true;
    }
    
    // Release tokens from timelock
    function releaseTimelock() returns (bool success) {
        if (timelockAmount[msg.sender] <= 0) throw;
        
        // Vulnerable: Uses block.timestamp (now) for time comparison
        // Miners can manipulate timestamp within certain bounds
        if (now < timelockActivated[msg.sender]) throw;
        
        uint256 amount = timelockAmount[msg.sender];
        timelockAmount[msg.sender] = 0;
        timelockActivated[msg.sender] = 0;
        
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], amount);
        
        TimelockReleased(msg.sender, amount);
        return true;
    }
    
    // Owner can modify timelock duration
    function setTimelockDuration(uint256 _duration) returns (bool success) {
        if (msg.sender != owner) throw;
        if (_duration <= 0) throw;
        
        timelockDuration = _duration;
        return true;
    }
    // === END FALLBACK INJECTION ===

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
        return true;
    }
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) {
		if(msg.sender != owner) throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() payable {
    }
}
