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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **State Persistence Requirement**: The vulnerability exploits the fact that balances and totalSupply persist between transactions. An attacker can accumulate state changes across multiple mint operations.
 * 
 * 2. **Multi-Transaction Exploitation Sequence**:
 *    - Transaction 1: Owner calls mint() for attacker's contract
 *    - During onTokenReceived callback, attacker's contract calls another function that depends on the old balance state
 *    - Transaction 2: Attacker uses the accumulated inconsistent state to perform unauthorized operations
 *    - The vulnerability requires the attacker to have a prepared contract and execute multiple coordinated transactions
 * 
 * 3. **External Call Before State Update**: The TokenRecipient(_to).onTokenReceived() call happens before balances[_to] and totalSupply are updated, creating a window where the contract state is inconsistent.
 * 
 * 4. **Realistic Attack Vector**: This pattern is common in token contracts that notify recipients about transfers, making it a realistic vulnerability that could appear in production code.
 * 
 * 5. **Stateful Nature**: The vulnerability accumulates effects across multiple mint operations - an attacker could trigger multiple reentrancy calls, each adding to the inconsistent state, requiring coordination across multiple transactions to fully exploit.
 * 
 * The vulnerability requires the attacker to: (1) Deploy a malicious contract that implements onTokenReceived, (2) Have the owner mint tokens to that contract, (3) Use the callback to trigger additional state-dependent operations, and (4) Execute follow-up transactions to capitalize on the accumulated inconsistent state. This makes it a genuine multi-transaction, stateful vulnerability.
 */
pragma solidity ^0.4.8;

contract Ownable {
	address owner;

	function Ownable() public {
		owner = msg.sender;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}

	function transfertOwnership(address newOwner) onlyOwner public {
		owner = newOwner;
	}
}

interface TokenRecipient {
    function onTokenReceived(address _from, uint _value) external;
}

contract EuroSibEnergo_CIP_IV_20180621 is Ownable {

	string public constant name = "\tEuroSibEnergo_CIP_IV_20180621\t\t";
	string public constant symbol = "\tESECIPIV\t\t";
	uint32 public constant decimals = 18;
	uint public totalSupply = 0;

	mapping (address => uint) balances;
	mapping (address => mapping(address => uint)) allowed;

	function mint(address _to, uint _value) onlyOwner public {
		assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

		// External call to recipient contract for notification before state update
		if (isContract(_to)) {
			TokenRecipient(_to).onTokenReceived(msg.sender, _value);
		}

		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balances[_to] += _value;
		totalSupply += _value;
	}

	function isContract(address _addr) internal view returns (bool) {
		uint length;
		assembly { length := extcodesize(_addr) }
		return length > 0;
	}

	function balanceOf(address _owner) public constant returns (uint balance) {
		return balances[_owner];
	}

	function transfer(address _to, uint _value) public returns (bool success) {
		if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
			balances[msg.sender] -= _value;
			balances[_to] += _value;
			return true;
		}
		return false;
	}

	function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
		if( allowed[_from][msg.sender] >= _value &&
			balances[_from] >= _value
			&& balances[_to] + _value >= balances[_to]) {
			allowed[_from][msg.sender] -= _value;
			balances[_from] -= _value;
			balances[_to] += _value;
			Transfer(_from, _to, _value);
			return true;
		}
		return false;
	}

	function approve(address _spender, uint _value) public returns (bool success) {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
		return true;
	}

	function allowance(address _owner, address _spender) public constant returns (uint remaining) {
		return allowed[_owner][_spender];
	}

	event Transfer(address indexed _from, address indexed _to, uint _value);
	event Approval(address indexed _owner, address indexed _spender, uint _value);
}
