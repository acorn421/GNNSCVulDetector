/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawUnlockMonth
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding a bonus reward system that depends on block.timestamp calculations. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `lastWithdrawalTime[msg.sender]` state tracking to store withdrawal timestamps
 * 2. Implemented a bonus multiplier system based on time elapsed since last withdrawal
 * 3. Used `block.timestamp` (now) for bonus calculations without proper validation
 * 4. Made the bonus persistent across transactions through state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `withdrawUnlockMonth()` to establish initial `lastWithdrawalTime`
 * 2. **Timestamp Manipulation**: Attacker collaborates with miner or waits for favorable block timestamps
 * 3. **Transaction 2**: Attacker calls `withdrawUnlockMonth()` again when block.timestamp shows artificially inflated time difference
 * 4. **Bonus Exploitation**: Receives 1.5x or 2x bonus multiplier on withdrawal amounts due to manipulated timestamp difference
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the difference between `lastWithdrawalTime` (set in first transaction) and current `block.timestamp` (used in second transaction)
 * - State must persist between transactions to track the last withdrawal time
 * - The bonus calculation requires comparing timestamps across different blocks/transactions
 * - Single transaction cannot exploit this as it requires temporal separation to show elapsed time
 * 
 * **Realistic Attack Vector:**
 * - Miners can manipulate block timestamps within ~15 minutes tolerance
 * - Attackers can wait for natural timestamp variations or coordinate with miners
 * - The bonus system appears as legitimate incentive mechanism but creates timestamp dependence vulnerability
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
contract GDU is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;
	
	uint256 createTime;
	
	address addr1;
	address addr2;
	address addr3;
	address addr4;
	

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;
    // --- ADDED ---
    mapping(address => uint256) public lastWithdrawalTime;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function GDU() public {
        balanceOf[msg.sender] = 15 * (10 ** 8) * (10 ** 18);              // Give the creator all initial tokens
        totalSupply =  100 * (10 ** 8) * (10 ** 18);                        // Update total supply
        name = "GD Union";                                   // Set the name for display purposes
        symbol = "GDU";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
		owner = msg.sender;
		createTime = now;
		
		addr1 = 0xa201967b67fA4Da2F7f4Cc2a333d2594fC44d350;
		addr2 = 0xC49909D6Cc0B460ADB33E591eC314DC817E9d200;
		addr3 = 0x455A3Ac6f11e6c301E4e5996F26EfaA76c549474;
		addr4 = 0xA93EAe1Db16F8710293a505289B0c8C34af5332F;
	
		for(uint256 i2 = 0;i2 < 10;i2++) { // changed int to uint256, 'i2' to avoid shadow with later for-loop variable
		    mouthUnlockList.push(0.5 * (10 ** 8) * (10 ** 18));
		}
		addrCanWithdraw[addr1] = mouthUnlockList;
		addrCanWithdraw[addr2] = mouthUnlockList;
		addrCanWithdraw[addr3] = mouthUnlockList;
		
		for(uint256 year = 0;year < 4;year++) {
		    yearUnlockList.push(10 * (10 ** 8) * (10 ** 18) + year * 5 * (10 ** 8) * (10 ** 18));
		}
		addrCanWithdraw[addr4] = yearUnlockList;
		
    }
    
    uint256[] mouthUnlockList;
    uint256[] yearUnlockList;
    mapping (address => uint256[]) addrCanWithdraw;
    
    modifier onlyMounthWithdrawer {
        require(msg.sender == addr1 || msg.sender == addr2 || msg.sender == addr3 );
        _;
    }
    modifier onlyYearWithdrawer {
        require(msg.sender == addr4 );
        _;
    }
    
    function withdrawUnlockMonth() onlyMounthWithdrawer {
        uint256 currentTime = now;
        uint256 times = (currentTime  - createTime) / (2190 hours);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the last withdrawal timestamp for future reference
        if (lastWithdrawalTime[msg.sender] == 0) {
            lastWithdrawalTime[msg.sender] = currentTime;
        }
        
        // Calculate bonus multiplier based on time since last withdrawal
        uint256 timeSinceLastWithdrawal = currentTime - lastWithdrawalTime[msg.sender];
        uint256 bonusMultiplier = 1 * (10 ** 18);
        
        // Vulnerable: Using block.timestamp for bonus calculation
        if (timeSinceLastWithdrawal > 30 days) {
            bonusMultiplier = 2 * (10 ** 18); // Double rewards for waiting
        } else if (timeSinceLastWithdrawal > 7 days) {
            bonusMultiplier = (15 * 10**17); // 1.5x rewards = 1.5 * 10^18
        }
        
        for(uint256 i = 0;i < times; i++) {
            uint256 withdrawAmount = addrCanWithdraw[msg.sender][i];
            if (withdrawAmount > 0) {
                // Apply bonus multiplier based on timestamp manipulation potential
                uint256 bonusAmount = (withdrawAmount * bonusMultiplier) / (10 ** 18);
                balanceOf[msg.sender] += bonusAmount;
                addrCanWithdraw[msg.sender][i] = 0;
            }
        }
        
        // Update last withdrawal time for next bonus calculation
        lastWithdrawalTime[msg.sender] = currentTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function withdrawUnlockYear() onlyYearWithdrawer {
        uint256 currentTime = now;
        require((currentTime  - createTime) > 0);
        uint256 times = (currentTime  - createTime) / (365 days);
        require(times <= 3);
        for(uint256 i = 0;i < times; i++) {
            balanceOf[msg.sender] += addrCanWithdraw[msg.sender][i];
            addrCanWithdraw[msg.sender][i] = 0;
        }
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
	function withdrawEther(uint256 amount) payable {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() payable {
    }
}
