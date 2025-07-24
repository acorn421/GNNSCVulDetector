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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability exploits the fact that external calls allow the recipient contract to reenter the mint function while the contract's state is in an inconsistent state.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` before state updates
 * 2. The call attempts to invoke `onTokensReceived(uint256)` on the recipient
 * 3. State modifications (balances and totalSupply updates) happen AFTER the external call
 * 4. This violates the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1:** Owner calls mint() for a malicious contract address
 * 2. **During Transaction 1:** The malicious contract's onTokensReceived() function is called
 * 3. **Reentrancy Window:** The malicious contract reenters mint() before balances are updated
 * 4. **State Inconsistency:** Multiple mint operations occur before any balance updates
 * 5. **Transaction 2+:** Subsequent legitimate transactions operate on corrupted state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires setting up a malicious contract that implements the callback
 * - The exploit accumulates state corruption over multiple mint operations
 * - Each reentrant call compounds the state inconsistency
 * - The attacker needs separate transactions to deploy the malicious contract and trigger the exploit
 * - The vulnerability's impact grows with each successful reentrancy across multiple transactions
 * 
 * **Realistic Integration:**
 * - Recipient notifications are a common legitimate pattern in token contracts
 * - The external call appears as a feature enhancement for better UX
 * - Many developers would naturally add such notifications without considering reentrancy risks
 * - The vulnerability is subtle and would likely pass initial code review
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

contract Rusal_CIP_VI_20181220 is Ownable {

	string public constant name = "\tRusal_CIP_VI_20181220\t\t";
	string public constant symbol = "\tRUSCIPVI\t\t";
	uint32 public constant decimals = 18;
	uint public totalSupply = 0;

	mapping (address => uint) balances;
	mapping (address => mapping(address => uint)) allowed;

	function mint(address _to, uint _value) public onlyOwner {
		assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Add external call to notify recipient before state updates
		// This creates a reentrancy window where state is inconsistent
		if (isContract(_to)) {
			bool success = _to.call(bytes4(keccak256("onTokensReceived(uint256)")), _value);
			require(success, "Recipient notification failed");
		}
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balances[_to] += _value;
		totalSupply += _value;
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
