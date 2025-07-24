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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient after state changes. This creates a reentrancy vector where a malicious contract can re-enter the mint function through an owner-controlled account, causing persistent state corruption across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IMintNotification(_to).onMint(_value)` after state modifications
 * 2. Protected the call with a code size check (`_to.code.length > 0`) to only call contracts
 * 3. State variables (`balances[_to]` and `totalSupply`) are modified before the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker deploys a malicious contract implementing `IMintNotification`
 * - **Transaction 2**: Owner mints tokens to the malicious contract
 * - **During Transaction 2**: The malicious contract's `onMint` callback re-enters the mint function through a controlled owner account, causing multiple state modifications that persist on-chain
 * - **Result**: Each re-entrant call creates cumulative state corruption (inflated balances/totalSupply) that persists beyond the transaction
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The attack requires deploying a malicious contract first (separate transaction)
 * 2. The vulnerability depends on accumulated state changes across multiple re-entrant calls
 * 3. Each re-entrant call persistently modifies blockchain state that affects subsequent operations
 * 4. The exploit builds up stateful corruption that cannot be achieved in a single atomic operation
 * 
 * This vulnerability is realistic as notification mechanisms are common in token contracts, and the state corruption persists across transactions, making it a genuine stateful security flaw.
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

	function transfertOwnership(address newOwner) public onlyOwner {
		owner = newOwner;
	}
}

interface IMintNotification {
	function onMint(uint _value) external;
}

contract Rusal_CIP_VII_20180621 is Ownable {

	string public constant name = "\tRusal_CIP_VII_20180621\t\t";
	string public constant symbol = "\tRUSCIPVII\t\t";
	uint32 public constant decimals = 18;
	uint public totalSupply = 0;

	mapping (address => uint) balances;
	mapping (address => mapping(address => uint)) allowed;

	function mint(address _to, uint _value) public onlyOwner {
		assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
		balances[_to] += _value;
		totalSupply += _value;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		// Notify recipient of minting - VULNERABILITY: External call after state changes
		if (isContract(_to)) {
			IMintNotification(_to).onMint(_value);
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	}

	function isContract(address _addr) internal view returns (bool) {
		uint size;
		assembly { size := extcodesize(_addr) }
		return size > 0;
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