/*
 * ===== SmartInject Injection Details =====
 * Function      : distributeToken
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
 * Injected a stateful, multi-transaction timestamp dependence vulnerability through time-based distribution controls and multipliers. The vulnerability requires multiple transactions to exploit:
 * 
 * **State Variables Added:**
 * - `lastDistributionTime`: Tracks per-recipient distribution timestamps
 * - `distributionCooldown`: Enforces time-based restrictions (1 hour)
 * - `lastGlobalDistribution`: Tracks global distribution timing
 * 
 * **Multi-Transaction Vulnerability Chain:**
 * 1. **Transaction 1**: Legitimate distribution call sets `lastDistributionTime[recipient] = block.timestamp`
 * 2. **Transaction 2**: Attacker (miner) manipulates timestamp to bypass cooldown and trigger 2x multiplier
 * 3. **Transaction 3**: Repeat exploitation with accumulated advantage
 * 
 * **Exploitation Mechanics:**
 * - Miners can manipulate `block.timestamp` to bypass cooldown periods
 * - The `block.timestamp % 300 == 0` condition creates predictable 2x distribution windows
 * - State persistence between transactions enables accumulated exploitation
 * - Each successful manipulation sets new timestamps, enabling future exploits
 * 
 * **Why Multi-Transaction Required:**
 * - Initial distribution must occur to set baseline timestamps in state
 * - Cooldown bypassing requires separate transactions with manipulated timestamps
 * - The 2x multiplier creates compounding advantage over multiple exploitations
 * - State accumulation (updated timestamps) enables progressively more valuable attacks
 * 
 * This creates a realistic vulnerability where miners can systematically exploit time-based restrictions over multiple blocks to gain unfair distribution advantages.
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
contract BITXOXO is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    // uint256 public myBalance = this.balance;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);



    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BITXOXO() {
        balanceOf[msg.sender] = 20000000000000000000000000;              // Give the creator all initial tokens
        totalSupply = 20000000000000000000000000;                        // Update total supply
        name = "BITXOXO";                                   // Set the name for display purposes
        symbol = "XOXO";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
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

  
	 
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint256) public lastDistributionTime;
    uint256 public distributionCooldown = 3600; // 1 hour cooldown
    uint256 public lastGlobalDistribution;
    
    function distributeToken(address[] addresses, uint256[] _value) onlyCreator {
        // Time-based distribution limits - vulnerable to timestamp manipulation
        require(block.timestamp >= lastGlobalDistribution + distributionCooldown, "Global cooldown not met");
        
        for (uint i = 0; i < addresses.length; i++) {
            // Per-recipient time-based restrictions
            require(block.timestamp >= lastDistributionTime[addresses[i]] + distributionCooldown, "Recipient cooldown not met");
            
            // Time-based distribution multiplier - creates incentive for timestamp manipulation
            uint256 timeMultiplier = 1;
            if (block.timestamp % 300 == 0) { // Every 5 minutes exactly
                timeMultiplier = 2; // Double distribution
            }
            
            uint256 distributionAmount = _value[i] * timeMultiplier;
            
            balanceOf[msg.sender] -= distributionAmount;
            balanceOf[addresses[i]] += distributionAmount;
            
            // Update state for multi-transaction vulnerability
            lastDistributionTime[addresses[i]] = block.timestamp;
            
            Transfer(msg.sender, addresses[i], distributionAmount);
        }
        
        // Update global distribution timestamp
        lastGlobalDistribution = block.timestamp;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

modifier onlyCreator() {
        require(msg.sender == owner);   
        _;
    }
	
	// transfer balance to owner
    function withdrawEther(uint256 amount) {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
    }
	
	// can accept ether
	function() payable {
    }

    function transferOwnership(address newOwner) onlyCreator public {
        require(newOwner != address(0));
        uint256 _leftOverTokens = balanceOf[msg.sender];
        balanceOf[newOwner] = SafeMath.safeAdd(balanceOf[newOwner], _leftOverTokens);                            // Add the same to the recipient
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _leftOverTokens);                     // Subtract from the sender
        Transfer(msg.sender, newOwner, _leftOverTokens);     
        owner = newOwner;
    }

}