/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_recipient.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` after the balance check but before state updates
 * 2. Added a check for contract code existence using `_recipient.code.length > 0` to make the call realistic
 * 3. The external call occurs before `balances[msg.sender] -= _value` and `balances[_recipient] += _value`, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract and receives initial tokens through normal transfers
 * 2. **Transaction 2+**: When someone transfers tokens to the malicious contract, it triggers the `onTokenReceived` callback
 * 3. **Reentrancy Chain**: The malicious contract's `onTokenReceived` function calls `transfer` again, creating a new transaction context
 * 4. **State Accumulation**: Each reentrant call occurs after the balance check but before the balance update, allowing the attacker to drain funds across multiple transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - Each reentrant call creates a new transaction context with fresh gas limits
 * - The attacker needs to build up token balances over multiple legitimate transactions first
 * - The vulnerability exploits the timing between the external call and state updates across transaction boundaries
 * - Gas limits prevent single-transaction exploitation, making this a true multi-transaction vulnerability
 * 
 * **Realistic Integration:**
 * - The notification mechanism mimics modern token standards (ERC-777, ERC-1155) that notify recipients
 * - The code appears as a legitimate enhancement for better user experience
 * - The vulnerability is subtle and would be difficult to spot in code reviews
 */
pragma solidity ^0.4.11;

contract Pi {
	uint256 public totalSupply;
	string public name;
	uint256 public decimals;
	string public symbol;
	address public owner;

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint256)) allowed;

    function Pi(uint256 _totalSupply, string _symbol, string _name, uint8 _decimalUnits) public {
        decimals = _decimalUnits;
        symbol = _symbol;
        name = _name;
        owner = msg.sender;
        totalSupply = _totalSupply * (10 ** decimals);
        balances[msg.sender] = totalSupply;
    }

	//Fix for short address attack against ERC20
	modifier onlyPayloadSize(uint size) {
		assert(msg.data.length == size + 4);
		_;
	} 

	function balanceOf(address _owner) constant public returns (uint256) {
		return balances[_owner];
	}

	function transfer(address _recipient, uint256 _value) onlyPayloadSize(2*32) public {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	require(balances[msg.sender] >= _value && _value > 0);
    
    // Notify recipient of incoming transfer (vulnerable external call)
    if (isContract(_recipient)) {
        // Vulnerable external call
        _recipient.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        // Continue regardless of call success to maintain functionality
    }
    
    balances[msg.sender] -= _value;
    balances[_recipient] += _value;
    Transfer(msg.sender, _recipient, _value);        
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function transferFrom(address _from, address _to, uint256 _value) public {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

	function approve(address _spender, uint256 _value) public {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
	}

	function allowance(address _owner, address _spender) constant public returns (uint256) {
		return allowed[_owner][_spender];
	}

	function mint(uint256 amount) public {
		assert(amount >= 0);
		require(msg.sender == owner);
		balances[msg.sender] += amount;
		totalSupply += amount;
	}

	// Utility function to check if an address is a contract
	function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

	//Event which is triggered to log all transfers to this contract's event log
	event Transfer(
		address indexed _from,
		address indexed _to,
		uint256 _value
		);
		
	//Event which is triggered whenever an owner approves a new allowance for a spender.
	event Approval(
		address indexed _owner,
		address indexed _spender,
		uint256 _value
		);

}
