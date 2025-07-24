/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback after balance updates but before allowance reduction. The vulnerability requires multiple transactions to exploit:
 * 
 * **EXPLOITATION SEQUENCE:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract as recipient
 * - Attacker calls transferFrom with their malicious contract as _to
 * - During onTokenReceived callback, the malicious contract:
 *   - Records that balances have been updated but allowances haven't been reduced yet
 *   - Sets up attack state for subsequent transactions
 *   - Can observe intermediate state where balances are updated but allowances remain unchanged
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls transferFrom again with same parameters
 * - The malicious contract's onTokenReceived callback now:
 *   - Exploits the accumulated state knowledge from previous transaction
 *   - Can perform additional transfers using the same allowance (since allowance wasn't reduced in previous incomplete state)
 *   - Manipulates internal accounting based on observed state patterns
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on the attacker learning about the contract's state update patterns across multiple calls
 * 2. **Allowance Exploitation**: The attacker needs to accumulate knowledge about when allowances are reduced vs when balances are updated
 * 3. **Gas Limits**: Single-transaction reentrancy would hit gas limits; multi-transaction allows more complex manipulation
 * 4. **State Persistence**: The malicious contract can store information between transactions about the token contract's intermediate states
 * 
 * **REALISTIC SCENARIO:**
 * This mimics real-world token notification patterns (like ERC777) where recipients need to be notified of incoming transfers, but the placement of the external call creates a window for multi-transaction exploitation of the approval mechanism.
 */
pragma solidity ^0.4.11;

contract PFG {
	uint256 public totalSupply;
	bool public mintable;
	string public name;
	uint256 public decimals;
	string public symbol;
	address public owner;

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint256)) allowed;

  function PFG(uint256 _totalSupply, string _symbol, string _name, bool _mintable) public {
		decimals = 18;
		symbol = _symbol;
		name = _name;
		mintable = _mintable;
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
	    emit Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint256 _value) public {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient of incoming transfer (vulnerability injection point)
        if (extcodesize(_to) > 0) {
            // The next line simulates the notification call as in the original code
            // This structure is compatible with Solidity 0.4.x
            require(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
    }

	function approve(address _spender, uint256 _value) public {
		allowed[msg.sender][_spender] = _value;
		emit Approval(msg.sender, _spender, _value);
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

    // Add extcodesize helper, only possible in 0.4.x
    function extcodesize(address _addr) internal view returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }
}
