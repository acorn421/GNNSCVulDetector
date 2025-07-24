/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: The function now makes an external call to `msg.sender.call()` to notify about freeze bonuses, but this call happens BEFORE the critical state updates (balanceOf and freezeOf modifications).
 * 
 * 2. **State-Dependent Threshold Logic**: The vulnerability depends on accumulated frozen tokens (`totalFrozen >= bonusThreshold`), requiring multiple freeze transactions to reach the threshold and trigger the vulnerable code path.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1-N**: Attacker calls freeze() multiple times to accumulate frozen tokens until reaching the 10,000 token threshold
 *    - **Transaction N+1**: When threshold is reached, the external call is triggered, but state updates haven't occurred yet
 *    - **Reentrancy Window**: The external call can reenter freeze() function, seeing the old state where balanceOf hasn't been updated yet
 *    - **State Manipulation**: Attacker can exploit the timing window to freeze more tokens than they actually own
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability only triggers after accumulating sufficient frozen tokens across multiple transactions
 *    - Single transaction cannot exploit this because the threshold must be built up over time
 *    - The reentrancy window only opens after reaching the accumulated state threshold
 *    - Each transaction builds the state required for the final exploitation
 * 
 * 5. **Realistic Context**: The bonus notification system is a plausible feature for a token contract, making this vulnerability subtle and realistic.
 */
pragma solidity ^0.4.18;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
}
contract AC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
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

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function AC(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        address holder)  public{
        totalSupply = initialSupply * 10 ** uint256(decimals); // Update total supply
        balanceOf[holder] = totalSupply;                       // Give the creator all initial tokens
        name = tokenName;                                      // Set the name for display purposes
        symbol = tokenSymbol;                                  // Set the symbol for display purposes
		owner = holder;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        require(_to != 0x0);  // Prevent transfer to 0x0 address. Use burn() instead
		require(_value > 0); 
        require(balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        require(_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
		require(_value > 0); 
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Calculate freeze bonus for large amounts (accumulated across multiple freezes)
        uint256 totalFrozen = freezeOf[msg.sender];
        uint256 bonusThreshold = 10000 * 10**18; // 10,000 tokens
        
        if (totalFrozen >= bonusThreshold) {
            // Notify external reward contract about bonus eligibility
            // This external call happens BEFORE state updates are finalized
            if (msg.sender.call.value(0)(bytes4(keccak256("onFreezeBonus(address,uint256,uint256)")), msg.sender, _value, totalFrozen)) {
                // External call succeeded - bonus notification sent
            }
        }
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates frozen amount
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }

	// can accept ether
	function() payable public{
    }
}