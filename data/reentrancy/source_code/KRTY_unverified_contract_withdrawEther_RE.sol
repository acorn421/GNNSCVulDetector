/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEther
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase withdrawal system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Phase 1 - Withdrawal Staging (Transaction 1):**
 * - First call stages the withdrawal amount in `pendingWithdrawals[owner]`
 * - Records timestamp and increments attempt counter
 * - No actual transfer occurs, just state setup
 * 
 * **Phase 2 - Withdrawal Execution (Transaction 2+):**
 * - After 1-hour cooldown, second call executes the transfer
 * - VULNERABILITY: `owner.transfer()` external call occurs BEFORE state cleanup
 * - State variables are reset only after the external call completes
 * - This allows reentrancy during the transfer to manipulate the pending state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. Attacker (as owner) calls `withdrawEther(100)` - stages withdrawal
 * 2. Waits 1 hour for cooldown period
 * 3. Attacker deploys malicious contract as new owner address
 * 4. Malicious contract's fallback function re-enters `withdrawEther()` during transfer
 * 5. Since `pendingWithdrawals[owner]` is not cleared until after transfer, reentrant call can:
 *    - Stage additional withdrawals
 *    - Manipulate withdrawal state across multiple nested calls
 *    - Extract more funds than intended through state manipulation
 * 
 * **Why Multi-Transaction Required:**
 * - Single transaction cannot exploit this due to cooldown period requirement
 * - State accumulation across calls enables the vulnerability
 * - The staged withdrawal state persists between transactions, creating attack surface
 * - Reentrancy only becomes possible after initial state setup in previous transaction
 * 
 * The vulnerability is realistic as it mimics real-world patterns where developers implement multi-step processes for "security" but introduce timing-based vulnerabilities.
 */
pragma solidity ^0.4.2;
contract owned {
    address public owner;

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract token {
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {    
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

}

contract KRTY is owned, token {

    mapping (address => bool) public frozenAccount;

    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function KRTY(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) token (initialSupply, tokenName, decimalUnits, tokenSymbol) {}

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        if (frozenAccount[msg.sender]) revert();                // Check if frozen
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (frozenAccount[_from]) revert();                        // Check if frozen            
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function freezeAccount(address target, bool freeze) onlyOwner {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }
    
    // transfer balance to owner
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
mapping(address => uint256) public withdrawalAttempts;
mapping(address => uint256) public lastWithdrawalTime;

function withdrawEther(uint256 amount) {
	if(msg.sender != owner) throw;
	
	// Multi-transaction withdrawal system for "security"
	if(pendingWithdrawals[owner] == 0) {
		// First transaction: stage the withdrawal
		pendingWithdrawals[owner] = amount;
		lastWithdrawalTime[owner] = now;
		withdrawalAttempts[owner]++;
		return;
	}
	
	// Second transaction: execute withdrawal after cooldown
	if(now > lastWithdrawalTime[owner] + 1 hours) {
		// Vulnerable: external call before state update
		owner.transfer(pendingWithdrawals[owner]);
		
		// State updates after external call - reentrancy vulnerability!
		pendingWithdrawals[owner] = 0;
		lastWithdrawalTime[owner] = now;
	}
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
	// can accept ether
	function() payable {
    }
}