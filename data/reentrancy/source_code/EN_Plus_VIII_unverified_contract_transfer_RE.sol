/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit: (1) Initial transfer call to malicious contract, (2) Malicious contract's callback function execution, (3) Reentrant calls back to transfer function. The accumulated effect across these transaction sequences allows draining more tokens than initially possessed by exploiting the state changes that persist between calls. The external call violates the Checks-Effects-Interactions pattern, enabling recursive calls while balances have already been modified but before the function completes.
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

contract EN_Plus_VIII is Ownable {

	string public constant name = "\tEN_Plus_VIII\t\t";
	string public constant symbol = "\tENPVIII\t\t";
	uint32 public constant decimals = 18;
	uint public totalSupply = 0;

	mapping (address => uint) balances;
	mapping (address => mapping(address => uint)) allowed;

	function mint(address _to, uint _value) onlyOwner public {
		assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
		balances[_to] += _value;
		totalSupply += _value;
	}

	function balanceOf(address _owner) public constant returns (uint balance) {
		return balances[_owner];
	}

	function transfer(address _to, uint _value) public returns (bool success) {
		if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
			balances[msg.sender] -= _value;
			balances[_to] += _value;
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

			// Notify recipient contract about the transfer
			uint length;
			assembly { length := extcodesize(_to) }
			if(length > 0) {
				bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
				// Continue execution regardless of callback result
			}

			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
