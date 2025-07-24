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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added recipient notification callback mechanism before balance updates
 * 2. Uses low-level call() to invoke onTokenReceived() on recipient contracts
 * 3. Violates Checks-Effects-Interactions pattern by placing external call before state modifications
 * 4. Maintains original function behavior while adding the vulnerability
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with onTokenReceived() callback
 * 2. **First Exploit Transaction**: Legitimate user transfers tokens to attacker's contract
 *    - External call triggers attacker's onTokenReceived() callback
 *    - In callback, attacker can call transfer() again while original transaction's state changes are pending
 *    - This creates inconsistent state where balances haven't been updated yet
 * 3. **Subsequent Transactions**: Attacker exploits the accumulated inconsistent state
 *    - Each reentrant call can drain more funds before state is properly updated
 *    - Multiple transactions build up exploitable state imbalances
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - Single transaction atomic nature would typically prevent simple reentrancy
 * - However, the callback mechanism allows building up state inconsistencies across calls
 * - Each transaction's partial execution creates persistent state that can be exploited in follow-up transactions
 * - The vulnerability requires accumulated state changes from multiple function invocations to be effectively exploited
 * - Attacker needs to build up sufficient state imbalance through repeated calls to drain significant funds
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions and persistent state manipulation to exploit effectively.
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
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    
	    // Add recipient notification before state updates (introduces reentrancy)
	    uint codeLength;
	    assembly { codeLength := extcodesize(_recipient) }
	    if (codeLength > 0) {
	        // Call recipient's onTokenReceived callback if it's a contract
	        bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256)"));
	        _recipient.call(sig, msg.sender, _value);
	    }
	    
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    balances[msg.sender] -= _value;
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
    constructor() public {
		totalSupply = 18000000000000000;
		name = "TheFund.io";
		decimals = 8;
		symbol = "TFIO";
		version = "1.0";
		balances[msg.sender] = totalSupply;
	}
}
