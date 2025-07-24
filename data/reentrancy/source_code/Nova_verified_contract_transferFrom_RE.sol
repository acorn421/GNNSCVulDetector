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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability requires multiple transactions to exploit: (1) First transaction sets up state by partially executing transferFrom with malicious recipient contract, (2) During the external call, the malicious contract can re-enter transferFrom or other functions while sender's balance and allowance are not yet decremented, (3) Subsequent transactions can exploit the inconsistent state to drain tokens. The external call creates a window where balances[_to] is updated but balances[_from] and allowed[_from][msg.sender] are not yet decremented, violating the checks-effects-interactions pattern and enabling multi-transaction exploitation through accumulated state manipulation.
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
	    emit Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint _value) {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
    
    // Update recipient balance first
    balances[_to] += _value;
    
    // Notify recipient contract about incoming transfer (external call before state cleanup)
    if (isContract(_to)) {
        // Call to potentially malicious contract before cleaning up state
        bool success = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        // Continue execution regardless of call result to maintain functionality
    }
    
    // State cleanup happens after external call - creates reentrancy window
    balances[_from] -= _value;
    allowed[_from][msg.sender] -= _value;
    
    emit Transfer(_from, _to, _value);
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function approve(address _spender, uint _value) {
		allowed[msg.sender][_spender] = _value;
		emit Approval(msg.sender, _spender, _value);
	}

	function allowance(address _owner, address _spender) constant returns (uint balance) {
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
    
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

}

contract Nova is ERC20Standard {
	constructor() public {
		totalSupply = 100000000*10**8;
		name = "Real estate blockchain for professionals";
		decimals = 8;
		symbol = "NOV";
		version = "1.0";
		balances[msg.sender] = totalSupply;
	}
}
