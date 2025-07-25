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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` that executes before the critical state modifications to `freezeOf` and `balanceOf`.
 * 
 * 2. **Violated CEI Pattern**: The original function followed Checks-Effects-Interactions correctly, but the modified version places the external call (Interaction) before the state changes (Effects), creating a reentrancy vulnerability.
 * 
 * 3. **Maintained Function Signature**: Preserved the original function signature and return behavior to maintain compatibility.
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onUnfreeze(uint256)` callback
 * - Attacker calls `freeze()` to lock tokens in `freezeOf[attacker]`
 * - State: `freezeOf[attacker] = X`, `balanceOf[attacker] = Y`
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Attacker calls `unfreeze(amount)` from malicious contract
 * - Function checks pass: `freezeOf[attacker] >= amount`
 * - External call triggers `onUnfreeze()` callback in attacker's contract
 * - **Critical Gap**: State variables haven't been updated yet!
 * 
 * **Transaction 3+ (Recursive Exploitation):**
 * - Inside the `onUnfreeze()` callback, attacker calls `unfreeze()` again
 * - The check `freezeOf[msg.sender] < _value` still passes because `freezeOf` hasn't been decremented yet
 * - Each recursive call can unfreeze the same amount multiple times
 * - Eventually, attacker can unfreeze more tokens than they actually have frozen
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The attacker needs to first freeze tokens in one transaction, then exploit the unfreezing in subsequent transactions.
 * 
 * 2. **Callback Setup**: The attacker must deploy a malicious contract with the callback function in a separate transaction before the exploit.
 * 
 * 3. **Cross-Transaction State Dependency**: The vulnerability depends on the state from previous transactions (frozen tokens) being present when the reentrancy occurs.
 * 
 * 4. **Persistent State Manipulation**: Each reentrant call relies on the persistent state from the original transaction, allowing the attacker to drain more tokens than they should have access to across multiple nested calls.
 * 
 * The vulnerability is stateful because it depends on the accumulated `freezeOf` balance from previous transactions and can only be exploited through multiple sequential calls that manipulate this persistent state.
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
	
	function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;                                       // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);        // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;                                       // Check if the sender has enough
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external callback about unfreeze before state changes
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // Callback successful, proceed with unfreeze
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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