/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimeLockedTransfer
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
 * This vulnerability introduces timestamp dependence through time-locked transfers. The exploit requires multiple transactions: first to initiate a time-locked transfer, then to claim it. The vulnerability lies in the reliance on block.timestamp for time-based logic, which can be manipulated by miners within certain bounds (typically 15 seconds). An attacker who is also a miner could manipulate the timestamp to claim time-locked transfers earlier than intended, bypassing the intended security delay. This is a stateful vulnerability as it persists state between transactions (timeLockedTransfers and transferUnlockTime mappings) and requires multiple function calls to exploit.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-03-03
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
contract NBT is SafeMath{
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
    // Mapping to track time-locked transfers
    mapping (address => mapping (address => uint256)) public timeLockedTransfers;
    mapping (address => mapping (address => uint256)) public transferUnlockTime;
    
    event TimeLockedTransferInitiated(address indexed from, address indexed to, uint256 value, uint256 unlockTime);
    event TimeLockedTransferClaimed(address indexed from, address indexed to, uint256 value);
    // === END FALLBACK INJECTION ===

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function NBT(
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /* Initiate a time-locked transfer that can be claimed after a delay */
    function initiateTimeLockedTransfer(address _to, uint256 _value, uint256 _lockDuration) returns (bool success) {
        if (_to == 0x0) throw;
        if (_value <= 0) throw;
        if (balanceOf[msg.sender] < _value) throw;
        if (_lockDuration < 60) throw; // Minimum 1 minute lock
        
        // Transfer tokens to contract state
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        timeLockedTransfers[msg.sender][_to] = SafeMath.safeAdd(timeLockedTransfers[msg.sender][_to], _value);
        
        // VULNERABILITY: Using block.timestamp for time-based logic
        // Miners can manipulate timestamp within certain bounds
        uint256 unlockTime = block.timestamp + _lockDuration;
        transferUnlockTime[msg.sender][_to] = unlockTime;
        
        TimeLockedTransferInitiated(msg.sender, _to, _value, unlockTime);
        return true;
    }
    
    /* Claim a time-locked transfer after the unlock time */
    function claimTimeLockedTransfer(address _from) returns (bool success) {
        uint256 transferAmount = timeLockedTransfers[_from][msg.sender];
        if (transferAmount <= 0) throw;
        
        // VULNERABILITY: Timestamp dependence - miners can manipulate this
        // An attacker miner could manipulate block.timestamp to claim early
        if (block.timestamp < transferUnlockTime[_from][msg.sender]) throw;
        
        // Clear the time-locked transfer
        timeLockedTransfers[_from][msg.sender] = 0;
        transferUnlockTime[_from][msg.sender] = 0;
        
        // Transfer tokens to recipient
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], transferAmount);
        
        TimeLockedTransferClaimed(_from, msg.sender, transferAmount);
        Transfer(_from, msg.sender, transferAmount);
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
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() payable {
    }
}
