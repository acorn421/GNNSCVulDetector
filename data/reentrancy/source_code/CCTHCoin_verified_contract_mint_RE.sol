/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingMints` and `mintingInProgress` mappings to track minting state across transactions
 * 2. **External Call Before State Updates**: Added an external call to `onMintNotification()` before critical state modifications
 * 3. **Vulnerable State Window**: Created a window where state can be manipulated between the external call and state updates
 * 4. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit effectively
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner calls `mint(1000)`, sets `mintingInProgress[owner] = true` and `pendingMints[owner] = 1000`
 * - **During External Call**: Attacker's contract receives `onMintNotification()` and can re-enter the mint function
 * - **Transaction 2**: Re-entrant call to `mint(500)` while first mint is still in progress, can manipulate the pending state
 * - **Result**: Multiple mints can be processed with stale or manipulated state values
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the accumulated state in `pendingMints` and `mintingInProgress` mappings
 * - Exploitation requires the external call to trigger a re-entrant call while the first transaction is still processing
 * - The state persistence between transactions allows for manipulation of mint amounts and supply calculations
 * - Single transaction exploitation is prevented by the state checks, but multi-transaction sequences can bypass these protections
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


    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingMints;
    mapping (address => bool) public mintingInProgress;
    
    function mint(uint256 _value) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if(msg.sender != owner)throw;
        else{
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Start minting process - mark as in progress
            mintingInProgress[msg.sender] = true;
            pendingMints[msg.sender] = _value;
            
            // External call to notify minting system before state updates
            if(msg.sender.call.value(0)(bytes4(keccak256("onMintNotification(uint256)")), _value)) {
                // External call succeeded, continue with minting
            }
            
            // State updates happen after external call - vulnerable to reentrancy
            if(mintingInProgress[msg.sender] && pendingMints[msg.sender] > 0) {
                uint256 mintAmount = pendingMints[msg.sender];
                mined_coin_supply -= mintAmount; // Remove from unspent supply
                balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], mintAmount);  // Add the same to the recipient
                
                // Clear pending state only after successful minting
                pendingMints[msg.sender] = 0;
                mintingInProgress[msg.sender] = false;
                
                updateSupply();
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
	
	// can accept ether
	function() payable {
    }
}