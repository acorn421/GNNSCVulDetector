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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that allows recipient contracts to re-enter during transfers. The vulnerability creates a window where the sender's balance is decremented but the recipient's balance is not yet incremented, enabling exploitation through multiple transactions. 
 * 
 * **Specific Changes Made:**
 * 1. Added a low-level call to `_recipient.call()` that invokes an `onTokenReceived` callback function
 * 2. Positioned the external call after sender balance deduction but before recipient balance increment
 * 3. The callback executes with partially updated state (sender balance decreased, recipient balance not yet increased)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to a malicious contract
 *    - Sender balance is decremented: `balances[sender] -= _value`
 *    - External callback triggers: `_recipient.call(onTokenReceived...)`
 *    - Malicious contract re-enters `transfer()` again in the callback
 *    - State is inconsistent: sender balance already reduced, recipient not yet credited
 * 
 * 2. **Transaction 2** (Reentrant call within callback):
 *    - The reentrant call sees the reduced sender balance from Transaction 1
 *    - Can potentially drain more tokens by exploiting the inconsistent state
 *    - Each reentrant call creates a new state window for exploitation
 * 
 * 3. **Subsequent Transactions**: 
 *    - Attacker can chain multiple reentrant calls
 *    - Each call exploits the accumulated state changes from previous calls
 *    - The vulnerability compounds across multiple transaction frames
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the external callback to trigger additional `transfer()` calls
 * - Each reentrant call depends on state changes from previous calls in the chain
 * - The exploitation builds upon accumulated state modifications across multiple call frames
 * - Single transaction exploitation is limited by gas constraints and the specific state windows created
 * - The most effective exploitation requires setting up the attack contract state across multiple transactions before executing the main attack sequence
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world patterns seen in token contracts with callback mechanisms.
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
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    
	    // VULNERABLE: External callback before completing all state updates
	    // This allows reentrancy with partially updated state
	    if(_isContract(_recipient)) {
	        // Call recipient contract's callback function
	        bool success = _recipient.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
	        // Continue execution regardless of callback success
	    }
	    
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    balances[_recipient] += _value;
	    Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint _value) {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

	function approve(address _spender, uint _value) {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
	}

	function allowance(address _owner, address _spender) constant returns (uint balance) {
		return allowed[_owner][_spender];
	}

	// Internal function to check if address is a contract (for pre-0.5.0 Solidity)
	function _isContract(address _addr) internal constant returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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

contract Nova is ERC20Standard {
	function Nova() public {
		totalSupply = 100000000*10**8;
		name = "Real estate blockchain for professionals";
		decimals = 8;
		symbol = "NOV";
		version = "1.0";
		balances[msg.sender] = totalSupply;
	}
}
