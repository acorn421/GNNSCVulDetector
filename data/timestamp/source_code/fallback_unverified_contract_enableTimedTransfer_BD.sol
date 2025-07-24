/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedTransfer
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
 * This injection introduces a timestamp dependence vulnerability through a timed transfer mechanism. The vulnerability is stateful and requires multiple transactions: 1) enableTimedTransfer() to set up the transfer with a time delay, 2) executeTimedTransfer() to complete the transfer after the delay. The vulnerability lies in the use of 'now' (block.timestamp) which can be manipulated by miners within certain bounds. A malicious miner could potentially manipulate timestamps to either delay or accelerate the execution of timed transfers, affecting the intended timing mechanism. This creates a multi-transaction attack vector where the state persists between the setup and execution calls.
 */
/**
 *Submitted for verification at Etherscan.io on 2017-07-06
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
contract VAT is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Timed transfer state variables - moved to contract level scope */
    mapping (address => uint256) public timedTransferAmount;
    mapping (address => uint256) public timedTransferUnlockTime;
    mapping (address => address) public timedTransferRecipient;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);
    
    event TimedTransferEnabled(address indexed from, address indexed to, uint256 amount, uint256 unlockTime);
    event TimedTransferExecuted(address indexed from, address indexed to, uint256 amount);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function VAT(
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
    // Enable a timed transfer that can be executed after a delay
    function enableTimedTransfer(address _to, uint256 _amount, uint256 _delaySeconds) returns (bool success) {
        if (_to == 0x0) throw;
        if (_amount <= 0) throw;
        if (_delaySeconds <= 0) throw;
        if (balanceOf[msg.sender] < _amount) throw;
        if (timedTransferAmount[msg.sender] > 0) throw; // Only one timed transfer per address
        
        // Lock the tokens by reducing balance
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
        
        // Store timed transfer details
        timedTransferAmount[msg.sender] = _amount;
        timedTransferRecipient[msg.sender] = _to;
        timedTransferUnlockTime[msg.sender] = now + _delaySeconds; // Vulnerable to timestamp manipulation
        
        TimedTransferEnabled(msg.sender, _to, _amount, timedTransferUnlockTime[msg.sender]);
        return true;
    }
    
    // Execute the timed transfer after the delay period
    function executeTimedTransfer() returns (bool success) {
        if (timedTransferAmount[msg.sender] <= 0) throw;
        if (now < timedTransferUnlockTime[msg.sender]) throw; // Vulnerable to timestamp manipulation
        
        address recipient = timedTransferRecipient[msg.sender];
        uint256 amount = timedTransferAmount[msg.sender];
        
        // Clear the timed transfer state
        timedTransferAmount[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
        timedTransferUnlockTime[msg.sender] = 0;
        
        // Execute the transfer
        if (balanceOf[recipient] + amount < balanceOf[recipient]) throw;
        balanceOf[recipient] = SafeMath.safeAdd(balanceOf[recipient], amount);
        
        TimedTransferExecuted(msg.sender, recipient, amount);
        Transfer(msg.sender, recipient, amount);
        return true;
    }
    
    // Cancel a pending timed transfer and return tokens
    function cancelTimedTransfer() returns (bool success) {
        if (timedTransferAmount[msg.sender] <= 0) throw;
        
        uint256 amount = timedTransferAmount[msg.sender];
        
        // Clear the timed transfer state
        timedTransferAmount[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
        timedTransferUnlockTime[msg.sender] = 0;
        
        // Return tokens to sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], amount);
        
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
//
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
