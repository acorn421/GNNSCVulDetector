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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient after state updates. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_recipient.call()` after all state modifications
 * 2. The call invokes `onTokenReceived(address,uint256)` callback on recipient contracts
 * 3. No reentrancy guard protection around the external call
 * 4. State updates occur before the external call, violating Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` callback
 * 2. **Transaction 2**: Legitimate user calls `transfer()` to send tokens to attacker's contract
 * 3. **During Transaction 2**: The external call triggers attacker's `onTokenReceived` callback
 * 4. **Reentrancy Attack**: Attacker's callback immediately calls `transfer()` again from the original sender's address
 * 5. **State Inconsistency**: The original sender's balance was already decremented, but the callback can trigger additional transfers before the transaction completes
 * 6. **Multiple Recursive Calls**: The attacker can drain funds through multiple recursive transfer calls within the same transaction context
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The actual exploitation occurs when someone transfers tokens to that contract (Transaction 2)
 * - The reentrancy attack leverages the persistent state changes (balance modifications) that occurred earlier in the transaction
 * - The attacker can potentially drain more funds than originally intended by exploiting the state inconsistency across multiple recursive calls
 * - Each recursive call operates on the modified state from previous calls, creating a cascading effect
 * 
 * **Realistic Vulnerability Pattern:**
 * This injection mimics real-world token contracts that implement recipient notification mechanisms (similar to ERC777 or ERC1363 patterns), making it a realistic vulnerability that could appear in production code while maintaining the function's intended transfer functionality.
 */
pragma solidity ^0.4.11;

contract ERC20Standard {

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint)) allowed;

	//Fix for short address attack against ERC20
	modifier onlyPayloadSize(uint size) {
		assert(msg.data.length == size + 4);
		_; 
	} 

	function balanceOf(address _owner) public constant returns (uint balance) {
	    return balances[_owner];
	}

	function transfer(address _recipient, uint _value) onlyPayloadSize(2*32) public {
		require(balances[msg.sender] >= _value && _value > 0);
	    balances[msg.sender] -= _value;
	    balances[_recipient] += _value;
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    emit Transfer(msg.sender, _recipient, _value);
	    
	    // Notify recipient contract if it implements the callback interface
	    uint256 codeLength;
        assembly { codeLength := extcodesize(_recipient) }
	    if (codeLength > 0) {
	        _recipient.call(
	            abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value)
	        );
	        // Continue execution regardless of callback success
	    }
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

	function transferFrom(address _from, address _to, uint _value) public {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
    }

	function approve(address _spender, uint _value) public {
		allowed[msg.sender][_spender] = _value;
		emit Approval(msg.sender, _spender, _value);
	}

	function allowance(address _owner, address _spender) public constant returns (uint balance) {
		return allowed[_owner][_spender];
	}

	//Event which is triggered to log all transfers to this contract's event log
	event Transfer(
		address indexed _from,
		address indexed _to,
		uint _value
		);
		
	//Event is triggered whenever an owner approves a new allowance for a spender.
	event Approval(
		address indexed _owner,
		address indexed _spender,
		uint _value
		);

}

contract WEBCOIN is ERC20Standard {
	string public name = "WEBCoin";
	uint8 public decimals = 18;
	string public symbol = "WEB";
	uint public totalSupply = 21000000000000000000000000;
	    
	constructor() public {
	    balances[msg.sender] = totalSupply;
	}
}
