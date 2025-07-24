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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first deploy a malicious contract and set up allowances in separate transactions
 * 2. **State Accumulation**: The vulnerability exploits the fact that allowances and balances persist between transactions
 * 3. **Reentrancy Mechanism**: The external call to `onTokenReceived` occurs before state updates, allowing the malicious contract to re-enter and manipulate the same allowance multiple times
 * 
 * **Exploitation Steps:**
 * - **Transaction 1**: Attacker gets approval for tokens from victim
 * - **Transaction 2**: Attacker calls transferFrom, triggering the malicious contract's onTokenReceived
 * - **Reentrancy**: The malicious contract re-enters transferFrom multiple times before the original call completes, draining more tokens than authorized
 * 
 * The vulnerability is stateful because it depends on pre-existing allowances and accumulated balance changes across multiple function calls. It cannot be exploited in a single transaction without this multi-transaction setup.
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
	    Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint _value) public {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (external call before state update)
        if (isContract(_to)) {
            TokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is contract
    function isContract(address _addr) private view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
    
    // Interface for contract recipients
    // Moved interface to outside the contract due to Solidity <0.5.0 limitation
    //interface TokenReceiver {
    //    function onTokenReceived(address _from, uint _value) external;
    //}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function approve(address _spender, uint _value) public {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
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

// Moved interface outside of contract for Solidity 0.4.x compatibility
contract TokenReceiver {
    function onTokenReceived(address _from, uint _value) external;
}

contract MODXCOIN is ERC20Standard {
	string public name = "MODEL-X-coin";
	uint8 public decimals = 8;
	string public symbol = "MODX";
	uint public totalSupply = 2100000000000000;
	    
	function MODXCOIN() {
	    balances[msg.sender] = totalSupply;
	}
}
