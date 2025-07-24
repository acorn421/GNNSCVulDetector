/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `freezeCallback` mapping to store user-registered callback contracts
 *    - `pendingFreezeAmount` mapping to track amounts being processed
 * 
 * 2. **Callback Registration Function**: Added `registerFreezeCallback()` to allow users to register external callback contracts
 * 
 * 3. **Vulnerable External Call**: Added external call to user-controlled callback contract BEFORE state updates, violating the Checks-Effects-Interactions pattern
 * 
 * 4. **State Persistence**: The `pendingFreezeAmount` state persists between transactions, creating stateful conditions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker calls `registerFreezeCallback(maliciousContract)` to register their malicious callback contract
 * 
 * **Transaction 2 (Initial Freeze)**: Attacker calls `freeze(100)`:
 * - `pendingFreezeAmount[attacker] = 100` is set
 * - External call to malicious contract occurs
 * - Malicious contract can call `freeze()` again recursively
 * - Due to state persistence, multiple freeze operations can manipulate the pending amounts
 * 
 * **Transaction 3+ (Exploitation)**: Through the callback mechanism, the attacker can:
 * - Manipulate the `pendingFreezeAmount` across multiple calls
 * - Exploit the fact that balance checks occur before the external call
 * - Use accumulated state changes to freeze more tokens than they actually have
 * - The vulnerability requires building up state across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The callback registration must occur in a separate transaction first
 * - The stateful nature of `pendingFreezeAmount` allows exploitation across transaction boundaries
 * - The attacker needs to accumulate state changes through multiple freeze operations
 * - Each transaction builds upon the persistent state from previous transactions
 * 
 * This creates a realistic vulnerability where the external integration feature (callback system) introduces a reentrancy flaw that can only be exploited through multiple transactions and persistent state manipulation.
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
contract CCTHCoin is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);
        
        string tokenName;
        uint8 decimalUnits;
        string tokenSymbol;
        uint256 public mined_coin_supply = 0;
        uint256 public pre_mined_supply = 0;
        uint256 public circulating_supply = 0;
        uint256 public reward = 5000000000;
        uint256 public timeOfLastHalving = now;
        uint public timeOfLastIncrease = now;
    
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CCTHCoin() {
        //balanceOf[msg.sender] = 2100000000000000;              // Give the creator all initial tokens
        totalSupply = 2100000000000000;                        // Update total supply
        name = "CryptoChips Coin";                            // Set the name for display purposes
        symbol = "CCTH";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
		owner = msg.sender;
        timeOfLastHalving = now;
    }

    function updateSupply() internal returns (uint256) {

      if (now - timeOfLastHalving >= 2100000 minutes) {
        reward /= 2;
        timeOfLastHalving = now;
      }

      if (now - timeOfLastIncrease >= 150 seconds) {
        uint256 increaseAmount = ((now - timeOfLastIncrease) / 60 seconds) * reward;
      if (totalSupply>(pre_mined_supply+increaseAmount))
        {
          pre_mined_supply += increaseAmount;
          mined_coin_supply += increaseAmount;
          timeOfLastIncrease = now;
        }
      }

      circulating_supply = pre_mined_supply - mined_coin_supply;

      return circulating_supply;
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);               // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient

        /* Notify anyone listening that the transfer took place */
        Transfer(msg.sender, _to, _value);

    }
    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;                                           // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);            // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => address) public freezeCallback;
    mapping (address => uint256) public pendingFreezeAmount;
    
    function freeze(uint256 _value) returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (balanceOf[msg.sender] < _value) throw;                                       // Check if the sender has enough
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending freeze amount for callback processing
        pendingFreezeAmount[msg.sender] = _value;
        
        // Call external callback if registered (before state updates)
        if (freezeCallback[msg.sender] != address(0)) {
            bytes4 sig = bytes4(keccak256("onFreezeCallback(address,uint256)"));
            freezeCallback[msg.sender].call(sig, msg.sender, _value);
        }
        
        // State updates occur after external call - vulnerable to reentrancy
        if (pendingFreezeAmount[msg.sender] > 0) {
            uint256 actualFreeze = pendingFreezeAmount[msg.sender];
            balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], actualFreeze);        // Subtract from the sender
            freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], actualFreeze);          // Add to frozen balance
            pendingFreezeAmount[msg.sender] = 0;
            Freeze(msg.sender, actualFreeze);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function registerFreezeCallback(address _callback) {
        freezeCallback[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;                                       // Check if the sender has enough
		if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);          // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}


    
    function mint(uint256 _value) {
        if(msg.sender != owner)throw;
        else{
            mined_coin_supply -= _value; // Remove from unspent supply
            balanceOf[msg.sender] =SafeMath.safeAdd(balanceOf[msg.sender], _value);  // Add the same to the recipient
            updateSupply();
        }

    }
	
	// can accept ether
	function() payable {
    }
}