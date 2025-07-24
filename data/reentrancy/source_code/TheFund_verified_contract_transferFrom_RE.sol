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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract via onTokenReceived() hook BEFORE the allowance is reduced. This creates a window where the recipient can re-enter the contract with the same allowance still available, but only after balances have been updated. The vulnerability requires multiple transactions: first to set up allowances, then to exploit the reentrancy window during transfer execution. The external call violates the checks-effects-interactions pattern by occurring between balance updates and allowance reduction, enabling cross-transaction exploitation scenarios.
 */
pragma solidity ^0.4.11;

contract ERC20Standard {
	uint public totalSupply;
	
	string public name;
	uint8 public decimals;
	string public symbol;
	string public version;
	
	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint)) allowed;

	//Fix for short address attack against ERC20
	modifier onlyPayloadSize(uint size) {
		assert(msg.data.length == size + 4);
		_;
	} 

	function balanceOf(address _owner) constant returns (uint balance) {
		return balances[_owner];
	}

	function transfer(address _recipient, uint _value) onlyPayloadSize(2*32) {
		require(balances[msg.sender] >= _value && _value > 0);
	    balances[msg.sender] -= _value;
	    balances[_recipient] += _value;
	    Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint _value) {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
    balances[_to] += _value;
    balances[_from] -= _value;
    
    // Transfer notification hook - allows recipient to react to incoming tokens
    if (isContract(_to)) {
        bytes4 sig = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
        _to.call(sig, _from, _to, _value);
    }
    
    allowed[_from][msg.sender] -= _value;
    Transfer(_from, _to, _value);
}

// Helper function to check if address is a contract
function isContract(address addr) private view returns (bool) {
    uint size;
    assembly { size := extcodesize(addr) }
    return size > 0;
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function approve(address _spender, uint _value) {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
	}

	function allowance(address _spender, address _owner) constant returns (uint balance) {
		return allowed[_owner][_spender];
	}

	//Event which is triggered to log all transfers to this contract's event log
	event Transfer(
		address indexed _from,
		address indexed _to,
		uint _value
		);
		
	//Event which is triggered whenever an owner approves a new allowance for a spender.
	event Approval(
		address indexed _owner,
		address indexed _spender,
		uint _value
		);

}

contract TheFund is ERC20Standard {
	function TheFund() {
		totalSupply = 18000000000000000;
		name = "TheFund.io";
		decimals = 8;
		symbol = "TFIO";
		version = "1.0";
		balances[msg.sender] = totalSupply;
	}
}