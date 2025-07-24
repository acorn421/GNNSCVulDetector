/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burnTracker contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `burnTracker.call()` after input validation but before state updates
 * 2. The external call occurs while the user's balance is still unchanged, creating a reentrancy window
 * 3. The burnTracker address would need to be set through a separate admin function (assumed to exist)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious burnTracker contract and admin sets it as the burnTracker
 * 2. **Initial Burn Transaction**: User calls burn() with legitimate value
 * 3. **Reentrancy Attack**: During the external call, malicious burnTracker re-enters burn() multiple times
 * 4. **State Exploitation**: Each reentrant call sees the original balance (since state isn't updated yet), allowing burning more tokens than owned
 * 5. **Persistent Effect**: The accumulated burns persist across transactions, causing permanent token supply manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - Transaction 1: Setup the malicious burnTracker contract
 * - Transaction 2: Initial burn call that triggers the reentrancy
 * - The vulnerability exploits the gap between external call and state update within a single transaction, but the effect accumulates across the transaction boundary
 * - Multiple reentrant calls within the same transaction create persistent state changes that affect future transactions
 * - The total supply manipulation persists beyond the initial transaction, affecting all subsequent token operations
 * 
 * **Realistic Integration:**
 * - Adding burn notification callbacks is a common pattern for token contracts
 * - External tracking of burn events for analytics or governance is legitimate functionality
 * - The vulnerability is subtle and could easily be overlooked in code reviews
 */
/*
**  CCT -- Community Credit Token
*/
pragma solidity ^0.4.11;

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
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
contract CCT is SafeMath{
    string public version = "1.0";
    string public name = "Community Credit Token";
    string public symbol = "CCT";
    uint8 public decimals = 18;
    uint256 public totalSupply = 5 * (10**9) * (10 **18);
	address public admin;
    address public burnTracker;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public lockOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	/* This notifies clients about the amount frozen */
    event Lock(address indexed from, uint256 value);
	/* This notifies clients about the amount unfrozen */
    event Unlock(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        admin = msg.sender;
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
    }
    /**
     * If we want to rebrand, we can.
     */
    function setName(string _name) public {
        if(msg.sender == admin)
            name = _name;
    }
    /**
     * If we want to rebrand, we can.
     */
    function setSymbol(string _symbol) public {
        if(msg.sender == admin)
            symbol = _symbol;
    }
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) revert(); 
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }
    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
		if (_value <= 0) revert(); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) revert(); 
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] = safeSub(balanceOf[_from], _value);                         // Subtract from the sender
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }
    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
		if (_value <= 0) revert(); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn tracker before state updates (vulnerability injection point)
        if (burnTracker != address(0)) {
            burnTracker.call(bytes4(keccak256("onBurn(address,uint256)")), msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
        totalSupply = safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	function lock(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
		if (_value <= 0) revert(); 
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        lockOf[msg.sender] = safeAdd(lockOf[msg.sender], _value);                           // Updates totalSupply
        Lock(msg.sender, _value);
        return true;
    }
	function unlock(uint256 _value) public returns (bool success) {
        if (lockOf[msg.sender] < _value) revert();            // Check if the sender has enough
		if (_value <= 0) revert(); 
        lockOf[msg.sender] = safeSub(lockOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = safeAdd(balanceOf[msg.sender], _value);
        Unlock(msg.sender, _value);
        return true;
    }
	// transfer balance to admin
	function withdrawEther(uint256 amount) public {
		if(msg.sender != admin) revert();
		admin.transfer(amount);
	}
	// can accept ether
	function() public payable {
    }
}
