/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `msg.sender.call(abi.encodeWithSignature("onMint(uint256)", amount))` before state updates
 * 2. Added require statement to enforce callback success, making the vulnerability more realistic
 * 3. Maintained all original function logic and access controls
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Owner deploys a malicious contract that implements onMint callback
 * 2. **Transaction 2**: Owner calls mint() from the malicious contract
 * 3. **During Transaction 2**: The external call triggers the onMint callback, which can re-enter mint() before state updates occur
 * 4. **State Persistence**: The accumulated balances and totalSupply from multiple reentrant calls persist across the transaction boundary
 * 
 * **Why Multi-Transaction Required:**
 * - The malicious contract must be deployed in a separate transaction first
 * - The vulnerability exploits the gap between the external call and state updates within a single mint() execution
 * - State changes (balances, totalSupply) accumulate across reentrant calls and persist after transaction completion
 * - Subsequent transactions can build upon the inflated state from previous exploits
 * 
 * **Realistic Scenario:**
 * This mimics real-world contracts that notify recipients of token mints through callbacks, making the vulnerability subtle and production-like while creating a classic reentrancy pattern.
 */
pragma solidity ^0.4.11;

contract OL {
	uint256 public totalSupply;
	string public name;
	uint256 public decimals;
	string public symbol;
	address public owner;

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint256)) allowed;

    function OL(uint256 _totalSupply, string _symbol, string _name, uint8 _decimalUnits) public {
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
		require(balances[msg.sender] >= _value && _value > 0);
	    balances[msg.sender] -= _value;
	    balances[_recipient] += _value;
	    Transfer(msg.sender, _recipient, _value);        
    }

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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// External call to notify recipient of mint operation
		(bool success, ) = msg.sender.call(abi.encodeWithSignature("onMint(uint256)", amount));
		require(success, "Mint notification failed");
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balances[msg.sender] += amount;
		totalSupply += amount;
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