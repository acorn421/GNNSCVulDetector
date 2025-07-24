/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawUnlockYear
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
 * Introduced a stateful timestamp dependence vulnerability by adding a time-based bonus system that relies on block.timestamp differences between withdrawal transactions. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variable Addition**: The code references `lastWithdrawalTime[msg.sender]` which stores the timestamp of the user's last withdrawal transaction.
 * 
 * 2. **Timestamp-Dependent Bonus Logic**: Added a bonus multiplier system that gives extra tokens (10-20% bonus) based on the time difference between consecutive withdrawal calls.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: User calls withdrawUnlockYear() to establish initial lastWithdrawalTime state
 *    - **Transaction 2**: User waits for optimal time window (15-30 minutes or 1-2 hours later) and calls again to receive bonus tokens
 *    - **Miner Manipulation**: Miners can manipulate block timestamps to artificially create the optimal time windows for maximum bonus extraction
 * 
 * 4. **Persistent State**: The lastWithdrawalTime mapping persists between transactions, enabling the vulnerability to accumulate benefits across multiple calls.
 * 
 * 5. **Realistic Implementation**: The bonus system appears as a legitimate feature to incentivize regular withdrawals, making the vulnerability subtle and realistic.
 * 
 * The vulnerability allows attackers (especially miners) to extract additional tokens by manipulating block timestamps to fall within the bonus time windows across multiple withdrawal transactions, potentially extracting significantly more tokens than intended over time.
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

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function GDU() {
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
	
		for(int i = 0;i < 10;i++) {
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
    
    mapping(address => uint256) lastWithdrawalTime;
    
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
        uint256 times = (currentTime  - createTime) / 2190 hours;
        for(uint256 i = 0;i < times; i++) {
            balanceOf[msg.sender] += addrCanWithdraw[msg.sender][i];
            addrCanWithdraw[msg.sender][i] = 0;
        }
    }
    
    function withdrawUnlockYear() onlyYearWithdrawer {
        uint256 currentTime = now;
        require((currentTime  - createTime) > 0);
        uint256 times = (currentTime  - createTime) / 1 years;
        require(times <= 3);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the last withdrawal timestamp for bonus calculation
        if (lastWithdrawalTime[msg.sender] == 0) {
            lastWithdrawalTime[msg.sender] = currentTime;
        }
        
        // Calculate time-based bonus multiplier for consecutive withdrawals
        uint256 timeDiff = currentTime - lastWithdrawalTime[msg.sender];
        uint256 bonusMultiplier = 100; // Base 100% (no bonus)
        
        // Bonus for withdrawals within specific time windows
        if (timeDiff >= 15 minutes && timeDiff <= 30 minutes) {
            bonusMultiplier = 120; // 20% bonus
        } else if (timeDiff >= 1 hours && timeDiff <= 2 hours) {
            bonusMultiplier = 110; // 10% bonus
        }
        
        for(uint256 i = 0;i < times; i++) {
            uint256 withdrawAmount = addrCanWithdraw[msg.sender][i];
            if (withdrawAmount > 0) {
                // Apply time-based bonus
                uint256 bonusAmount = (withdrawAmount * bonusMultiplier) / 100;
                balanceOf[msg.sender] += bonusAmount;
                addrCanWithdraw[msg.sender][i] = 0;
            }
        }
        
        // Update last withdrawal timestamp
        lastWithdrawalTime[msg.sender] = currentTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
