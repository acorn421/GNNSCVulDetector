/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEther
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking state that persists between transactions. The vulnerability requires: 1) First transaction to initialize withdrawal request, 2) Second transaction to execute withdrawal where reentrancy can manipulate pendingWithdrawals before state cleanup. The external call (owner.transfer) occurs before state updates, allowing a malicious owner contract to reenter and modify withdrawal amounts or initiate multiple withdrawals during the transfer callback.
 */
/**
 *Submitted for verification at Etherscan.io on 2017-07-06
*/

pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract CJZVIP is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CJZVIP(
        ) {
        balanceOf[msg.sender] = 30000000000000000000000000;              // Give the creator all initial tokens
        totalSupply = 30000000000000000000000000;                        // Update total supply
        name = "CJZVIP";                                   // Set the name for display purposes
        symbol = "CZ";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }


    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

	
	// transfer balance to owner
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
	mapping(address => bool) public withdrawalInitiated;
	
	function withdrawEther(uint256 amount) onlyOwner {
		if (!withdrawalInitiated[owner]) {
			// First call: Initialize withdrawal request
			pendingWithdrawals[owner] = amount;
			withdrawalInitiated[owner] = true;
		} else {
			// Subsequent calls: Execute withdrawal
			uint256 withdrawAmount = pendingWithdrawals[owner];
			if (withdrawAmount > 0 && address(this).balance >= withdrawAmount) {
				// External call BEFORE state update - vulnerable to reentrancy
				owner.transfer(withdrawAmount);
				
				// State update after external call - can be manipulated during reentrancy
				pendingWithdrawals[owner] = 0;
				withdrawalInitiated[owner] = false;
			}
		}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	}
	function MakeOver(address _to)onlyOwner{
	    owner = _to;
	}
	// can accept ether
	function() payable {
    }
}