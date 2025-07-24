/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeBasedUnlock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduces a multi-transaction timestamp dependence vulnerability where users can lock tokens for a time period, but the unlock mechanism relies on block.timestamp which can be manipulated by miners. The vulnerability requires: 1) First transaction to start the time lock, 2) Wait for the time period, 3) Second transaction to complete unlock. Miners can manipulate timestamps within ~15 seconds to either delay unlocks or reduce penalties in emergency unlocks.
 */
pragma solidity ^0.4.25;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) pure internal returns (uint256) {
    if (a == 0) {
      return 0;
    }

    uint256 c = a * b;
    require(c / a == b);

    return c;
  }

  function safeDiv(uint256 a, uint256 b) pure internal returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold

    return c;
  }

  function safeSub(uint256 a, uint256 b) pure internal returns (uint256) {
    require(b <= a);
    uint256 c = a - b;

    return c;
  }

  function safeAdd(uint256 a, uint256 b) pure internal returns (uint256) {
    uint256 c = a + b;
    require(c >= a);

    return c;
  }
  
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }

  /*function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }*/
}
/**
 * Smart Token Contract modified and developed by Marco Sanna,
 * blockchain developer of Namacoin ICO Project.
 */
contract Namacoin is SafeMath{
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
	
	/* This notifies clients that owner withdraw the ether */
	event Withdraw(address indexed from, uint256 value);
	
	/* This notifies the first creation of the contract */
	event Creation(address indexed owner, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-based unlocking mechanism
    mapping (address => uint256) public timeLockedBalances;
    mapping (address => uint256) public unlockTimestamp;
    uint256 public constant UNLOCK_DURATION = 7 days;
    
    /* Events for time-based operations */
    event TimeLockStarted(address indexed user, uint256 amount, uint256 unlockTime);
    event TimeLockCompleted(address indexed user, uint256 amount);
    event EmergencyUnlock(address indexed user, uint256 returned, uint256 penalty);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        emit Creation(msg.sender, initialSupply);                // Notify anyone that the Tokes was create 
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }
    
    /* Start time-based unlock process for tokens */
    function startTimeBasedUnlock(uint256 _value) public returns (bool success) {
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(timeLockedBalances[msg.sender] == 0); // No existing lock
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        timeLockedBalances[msg.sender] = _value;
        // Vulnerability: Using block.timestamp for time-sensitive operations
        unlockTimestamp[msg.sender] = block.timestamp + UNLOCK_DURATION;
        
        emit TimeLockStarted(msg.sender, _value, unlockTimestamp[msg.sender]);
        return true;
    }
    
    /* Complete the time-based unlock and retrieve tokens */
    function completeTimeBasedUnlock() public returns (bool success) {
        require(timeLockedBalances[msg.sender] > 0);
        // Vulnerability: Miners can manipulate block.timestamp within bounds
        require(block.timestamp >= unlockTimestamp[msg.sender]);
        
        uint256 unlockedAmount = timeLockedBalances[msg.sender];
        timeLockedBalances[msg.sender] = 0;
        unlockTimestamp[msg.sender] = 0;
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], unlockedAmount);
        
        emit TimeLockCompleted(msg.sender, unlockedAmount);
        return true;
    }
    
    /* Emergency unlock with penalty (owner only) */
    function emergencyUnlock(address _user) public returns (bool success) {
        require(msg.sender == owner);
        require(timeLockedBalances[_user] > 0);
        // Vulnerability: Time manipulation affects penalty calculation
        uint256 remainingTime = unlockTimestamp[_user] > block.timestamp ? 
                                unlockTimestamp[_user] - block.timestamp : 0;
        
        uint256 penaltyAmount = SafeMath.safeDiv(
            SafeMath.safeMul(timeLockedBalances[_user], remainingTime), 
            UNLOCK_DURATION
        );
        uint256 returnAmount = SafeMath.safeSub(timeLockedBalances[_user], penaltyAmount);
        
        timeLockedBalances[_user] = 0;
        unlockTimestamp[_user] = 0;
        balanceOf[_user] = SafeMath.safeAdd(balanceOf[_user], returnAmount);
        
        emit EmergencyUnlock(_user, returnAmount, penaltyAmount);
        return true;
    }
    // === END FALLBACK INJECTION ===

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(_value <= allowance[_from][msg.sender]);
        
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
	    require(balanceOf[msg.sender] >= _value);
	    require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
	    require(freezeOf[msg.sender] >= _value);
	    require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) public returns (bool success){
	    require(msg.sender == owner);
		owner.transfer(amount);
		emit Withdraw(msg.sender, amount);
		return true;
	}
	
	// can accept ether
	function() public payable {
    }
}
