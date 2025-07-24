/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to recipient contracts after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation Phase**: The attacker must first accumulate sufficient balance through legitimate transfers or other means across multiple transactions
 * 2. **Attack Setup Phase**: The attacker deploys a malicious contract that implements the ITokenReceiver interface
 * 3. **Exploitation Phase**: When someone transfers tokens to the malicious contract, it can re-enter the transfer function during the callback
 * 
 * **Multi-Transaction Exploitation Requirements:**
 * - **Transaction 1-N**: Accumulate balance in victim accounts or set up initial state
 * - **Transaction N+1**: Deploy malicious receiver contract with reentrancy logic
 * - **Transaction N+2**: Trigger transfer to malicious contract, which re-enters during callback
 * - **Transaction N+3+**: Continue draining through multiple reentrancy calls
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Dependency**: The vulnerability depends on having sufficient balances in victim accounts, which must be accumulated over time
 * 2. **Contract Deployment**: The malicious receiver contract must be deployed in a separate transaction
 * 3. **Gradual Exploitation**: Each reentrancy call can only drain a limited amount, requiring multiple calls to fully exploit
 * 4. **State Persistence**: The balance state changes persist between transactions, enabling the accumulated exploitation
 * 
 * The vulnerability is realistic because callback patterns are common in modern token implementations for notifications and integrations. The external call after state updates violates the Checks-Effects-Interactions pattern, creating a classic reentrancy vulnerability that requires multiple transactions to fully exploit.
 */
pragma solidity ^0.4.11;

//------------------------------------------------------------------------------------------------
// ERC20 Standard Token Implementation, based on ERC Standard:
// https://github.com/ethereum/EIPs/issues/20
// With some inspiration from ConsenSys HumanStandardToken as well
// Copyright 2017 BattleDrome
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
// LICENSE
//
// This file is part of BattleDrome.
// 
// BattleDrome is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// BattleDrome is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with BattleDrome.  If not, see <http://www.gnu.org/licenses/>.
//------------------------------------------------------------------------------------------------

interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external;
}

contract PFG {
	uint256 public totalSupply;
	bool public mintable;
	string public name;
	uint256 public decimals;
	string public symbol;
	address public owner;

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint256)) allowed;

  function PFG(uint256 _totalSupply, string _symbol, string _name, bool _mintable) public {
		decimals = 18;
		symbol = _symbol;
		name = _name;
		mintable = _mintable;
		owner = msg.sender;
        totalSupply = _totalSupply * (10 ** decimals);
        balances[msg.sender] = totalSupply;
  }
	//Fix for short address attack against ERC20
	modifier onlyPayloadSize(uint size) {
		assert(msg.data.length == size + 4);
		_;
	} 

	function balanceOf(address _owner) constant public returns (uint256) {
		return balances[_owner];
	}

	function transfer(address _recipient, uint256 _value) onlyPayloadSize(2*32) public {
		require(balances[msg.sender] >= _value && _value > 0);
	    balances[msg.sender] -= _value;
	    balances[_recipient] += _value;
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    
	    // Notify recipient contract if it has a callback function
        if(isContract(_recipient)) {
            ITokenReceiver(_recipient).onTokenReceived(msg.sender, _value);
        }
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint256 _value) public {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

	function approve(address _spender, uint256 _value) public {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
	}

	function allowance(address _owner, address _spender) constant public returns (uint256) {
		return allowed[_owner][_spender];
	}

	function mint(uint256 amount) public {
		assert(amount >= 0);
		require(msg.sender == owner);
		balances[msg.sender] += amount;
		totalSupply += amount;
	}

	// Helper function to check if address is a contract
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

	//Event which is triggered to log all transfers to this contract's event log
	event Transfer(
		address indexed _from,
		address indexed _to,
		uint256 _value
		);
		
	//Event which is triggered whenever an owner approves a new allowance for a spender.
	event Approval(
		address indexed _owner,
		address indexed _spender,
		uint256 _value
		);

}
