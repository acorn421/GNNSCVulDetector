/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism that calls `onUnfreezeCallback(uint256)` on the calling contract if it has code (is a contract, not EOA).
 * 
 * 2. **Violation of CEI Pattern**: The external call is placed after initial checks but before the critical state updates (freezeOf and balanceOf modifications), violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Preserved Function Signature**: Maintained the exact same function signature, parameters, and return type.
 * 
 * 4. **Maintained Core Logic**: The function still performs its intended unfreezing operations.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract that implements `onUnfreezeCallback(uint256)`
 * - Attacker calls `freeze()` to freeze some tokens, building up `freezeOf[attackerContract]` balance
 * - This creates the persistent state needed for the attack
 * 
 * **Transaction 2 - Initial Exploitation:**
 * - Attacker's contract calls `unfreeze()` with a specific value
 * - The function performs checks and calls `onUnfreezeCallback()` on the attacker's contract
 * - In the callback, the attacker's contract calls `unfreeze()` again (reentrancy)
 * - Since `freezeOf[msg.sender]` hasn't been updated yet, the checks pass again
 * - This creates a recursive chain of calls
 * 
 * **Transaction 3 - State Accumulation:**
 * - Each reentrant call increments `balanceOf[attackerContract]` multiple times
 * - The attacker can then call `transfer()` to move the excess tokens elsewhere
 * - The vulnerability compounds across multiple reentrancy levels
 * 
 * **Why Multi-Transaction Nature is Required:**
 * 
 * 1. **State Accumulation**: The attacker needs to first freeze tokens (Transaction 1) to create the vulnerable state that enables the reentrancy attack.
 * 
 * 2. **Persistent State Dependencies**: The `freezeOf` mapping must contain a balance from previous transactions to pass the initial checks.
 * 
 * 3. **Economic Incentive**: The attacker needs sufficient frozen balance built up over time to make the attack profitable.
 * 
 * 4. **Callback Implementation**: The attacker must deploy a contract with the callback function in a separate transaction before exploitation.
 * 
 * 5. **Multi-Level Exploitation**: The most effective attacks would involve multiple unfreeze operations across different transactions to maximize the drained amount while avoiding detection.
 * 
 * The vulnerability creates a compound effect where each reentrant call during the callback can manipulate the same state variables before the first call completes, leading to balance inflation that persists across transaction boundaries.
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
        uint256 times = (currentTime  - createTime) / (2190 * 1 hours);
        for(uint256 i = 0;i < times; i++) {
            balanceOf[msg.sender] += addrCanWithdraw[msg.sender][i];
            addrCanWithdraw[msg.sender][i] = 0;
        }
    }
    
    function withdrawUnlockYear() onlyYearWithdrawer {
        uint256 currentTime = now;
        require((currentTime  - createTime) > 0);
        uint256 times = (currentTime  - createTime) / (365 * 24 * 1 hours);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to contract - allows reentrancy
        if (isContract(msg.sender)) {
            // External call to contract - allows reentrancy
            bool callSuccess = msg.sender.call(bytes4(keccak256("onUnfreezeCallback(uint256)")), _value);
            // Continue regardless of callback success for backward compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
    
    function isContract(address _addr) internal returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
