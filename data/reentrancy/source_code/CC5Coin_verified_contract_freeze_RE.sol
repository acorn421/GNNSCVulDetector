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
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding two external calls that occur at different stages of the freeze process. The vulnerability requires multiple transactions to accumulate sufficient frozen balance to trigger the second external call, which occurs after state changes and enables reentrancy exploitation.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added pre-state external call**: For freeze amounts > 1,000,000, calls a notification contract before state updates
 * 2. **Added post-state external call**: For accumulated frozen balances > 5,000,000, calls a freeze tracking contract after state updates
 * 3. **Preserved original functionality**: All original checks and state updates remain intact
 * 4. **Used realistic integration**: External calls appear as legitimate notification/tracking features
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1-N**: Attacker makes multiple freeze calls to accumulate freezeOf[attacker] > 5,000,000
 * 2. **Transaction N+1**: Attacker calls freeze() with sufficient balance, triggering the post-state external call
 * 3. **Reentrancy**: The malicious tracking contract calls back into freeze() before the original transaction completes
 * 4. **State Manipulation**: Reentrant calls can manipulate balanceOf and freezeOf while original transaction is still executing
 * 5. **Amplification**: Multiple reentrant calls can drain more tokens than the attacker originally had
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - The vulnerability only triggers when freezeOf[msg.sender] > 5,000,000, requiring state accumulation
 * - Attackers must build up frozen balance over multiple transactions before exploitation becomes possible
 * - The stateful nature means each transaction builds upon previous state changes
 * - Single transaction exploitation is prevented by the threshold requirement for triggering the vulnerable external call
 * 
 * **Exploitation Scenario:**
 * An attacker would deploy a malicious contract at the tracking address, make several freeze transactions to build up frozen balance, then trigger the final freeze call that enables reentrancy to drain the contract's token balance.
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
contract CC5Coin is SafeMath{
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
    function CC5Coin() {
        //balanceOf[msg.sender] = 2100000000000000;              // Give the creator all initial tokens
        totalSupply = 2100000000000000;                        // Update total supply
        name = "CChips Coin";                            // Set the name for display purposes
        symbol = "CC5";                               // Set the symbol for display purposes
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
        uint256 increaseAmount = ((now - timeOfLastIncrease) / 10 seconds) * reward;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add notification system for large freeze operations
        if (_value > 1000000) {
            // Call external notification contract before state update
            address notificationContract = 0x1234567890123456789012345678901234567890;
            notificationContract.call(bytes4(keccak256("notifyFreeze(address,uint256)")), msg.sender, _value);
        }
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);        // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);         // Updates freeze balance
        
        // Additional external call for freeze tracking after state changes
        if (freezeOf[msg.sender] > 5000000) {
            // This external call happens after state changes, enabling reentrancy
            address freezeTracker = 0x9876543210987654321098765432109876543210;
            freezeTracker.call(bytes4(keccak256("trackLargeFreeze(address,uint256)")), msg.sender, freezeOf[msg.sender]);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Freeze(msg.sender, _value);
        return true;
    }
	
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