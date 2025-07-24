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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before finalizing the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract recipients using `_recipient.code.length > 0`
 * 2. Introduced an external call to `onTokenReceived(address,uint256)` before updating the recipient's balance
 * 3. The external call occurs after the sender's balance is reduced but before the recipient's balance is increased
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Attacker calls `transfer()` to send tokens to their malicious contract
 * 3. **Reentrancy Trigger**: During the external call, the malicious contract calls `transfer()` again
 * 4. **State Manipulation**: Since sender's balance was already reduced but recipient's balance not yet increased, the check `balances[msg.sender] >= _value` may pass again
 * 5. **Accumulated Effect**: Multiple reentrant calls can drain more tokens than the attacker originally owned
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy the malicious contract (Transaction 1)
 * - Then trigger the vulnerable transfer (Transaction 2)
 * - The vulnerability exploits the state inconsistency between transactions where balances[msg.sender] is reduced but balances[_recipient] is not yet increased
 * - Each reentrant call within Transaction 2 can potentially transfer more tokens due to the CEI pattern violation
 * - The persistent state changes (balance reductions) accumulate across the reentrant calls within the transaction sequence
 * 
 * This creates a realistic token notification mechanism that violates the Checks-Effects-Interactions pattern, making it vulnerable to reentrancy attacks that require the attacker to have a contract deployed and ready to receive the callback.
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

contract PFGC {
	uint256 public totalSupply;
	bool public mintable;
	string public name;
	uint256 public decimals;
	string public symbol;
	address public owner;

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint256)) allowed;

  function PFGC(uint256 _totalSupply, string _symbol, string _name, bool _mintable) public {
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
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    
	    // Notify recipient if it's a contract - VULNERABILITY: External call before state finalization
	    uint256 codeLength;
	    assembly { codeLength := extcodesize(_recipient) }
	    if(codeLength > 0) {
	        // Call recipient's onTokenReceived function if it exists
	        bool success = _recipient.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
	        // Continue regardless of success to maintain functionality
	    }
	    
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    balances[_recipient] += _value;
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
