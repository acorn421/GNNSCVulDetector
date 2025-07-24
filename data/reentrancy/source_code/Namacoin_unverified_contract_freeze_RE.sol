/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller's contract before state updates. The vulnerability exploits the fact that:
 * 
 * 1. **External Call Before State Updates**: The function calls `msg.sender.call()` to notify about the freeze event BEFORE updating `balanceOf` and `freezeOf` state variables.
 * 
 * 2. **Multi-Transaction Exploitation**: An attacker can deploy a malicious contract that:
 *    - Transaction 1: Calls `freeze(100)` with 100 tokens in balance
 *    - The external call triggers the malicious contract's `onTokenFreeze()` function
 *    - Before the original `freeze()` completes state updates, the malicious contract can call `freeze()` again
 *    - Since `balanceOf` hasn't been updated yet, the balance check still passes
 *    - Transaction 2: The second `freeze()` call succeeds with the same balance check
 *    - Result: 200 tokens frozen while only having 100 tokens in balance
 * 
 * 3. **Stateful Vulnerability**: The vulnerability requires multiple transactions because:
 *    - The attacker must first fund their malicious contract with tokens
 *    - The exploit accumulates frozen tokens across multiple freeze operations
 *    - Each transaction builds upon the state confusion from previous transactions
 *    - The inconsistent state between actual balance and frozen amounts persists between transactions
 * 
 * 4. **Realistic Integration**: The external call appears as a legitimate notification mechanism that could be used for:
 *    - Triggering DeFi protocol integrations
 *    - Notifying staking contracts about frozen tokens
 *    - Updating external accounting systems
 *    - Interfacing with governance mechanisms
 * 
 * The vulnerability is only exploitable through multiple transactions because the attacker needs to set up the malicious contract, fund it with tokens, and then execute the reentrancy attack across several function calls to accumulate the inconsistent state.
 */
pragma solidity ^0.4.25;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) pure internal returns (uint256) {
    if (a == 0) {
      return 0;
    }

    uint256 c = a * b;
    require(c / a == b);

    return c;
  }

  function safeDiv(uint256 a, uint256 b) pure internal returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    return c;
  }

  function safeSub(uint256 a, uint256 b) pure internal returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }

  function safeAdd(uint256 a, uint256 b) pure internal returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
  
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }

  /*function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }*/
}
/**
 * Smart Token Contract modified and developed by Marco Sanna,
 * blockchain developer of Namacoin ICO Project.
 */
contract Namacoin is SafeMath{
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
	
	/* This notifies clients that owner withdraw the ether */
	event Withdraw(address indexed from, uint256 value);
	
	/* This notifies the first creation of the contract */
	event Creation(address indexed owner, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        emit Creation(msg.sender, initialSupply);                // Notify anyone that the Tokes was create 
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
            
        require(_value > 0);
		allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(_value <= allowance[_from][msg.sender]);
        
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
	    require(balanceOf[msg.sender] >= _value);
	    require(_value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify freezing event before state updates
        if (isContract(msg.sender)) {
            // This inline (low-level) call triggers potential reentrancy,
            // as intended for the vulnerability demonstration
            (bool callSuccess,) = msg.sender.call(
                abi.encodeWithSignature("onTokenFreeze(uint256)", _value)
            );
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }

    // Helper to check if address is a contract for pre-0.8.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
	    require(freezeOf[msg.sender] >= _value);
	    require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) public returns (bool success){
	    require(msg.sender == owner);
		owner.transfer(amount);
		emit Withdraw(msg.sender, amount);
		return true;
	}
	
	// can accept ether
	function() public payable {
    }
}
