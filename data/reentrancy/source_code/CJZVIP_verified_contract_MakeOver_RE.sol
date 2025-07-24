/*
 * ===== SmartInject Injection Details =====
 * Function      : MakeOver
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase ownership transfer process. The vulnerability requires multiple transactions to exploit:
 * 
 * **Phase 1 (First Transaction)**: The function checks if the target address is not already pending. If not, it sets the address as pending and makes an external call to notify the proposed owner, creating a reentrancy point.
 * 
 * **Phase 2 (Second Transaction)**: If the address is already pending, the function makes another external call for confirmation, then updates the owner state AFTER the external call.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 1. **Transaction 1**: Attacker calls MakeOver(maliciousContract) - this sets pendingOwners[maliciousContract] = true and calls onOwnershipProposed()
 * 2. **During the external call in Transaction 1**: The malicious contract can re-enter but cannot complete ownership transfer yet (still in pending state)
 * 3. **Transaction 2**: Attacker calls MakeOver(maliciousContract) again - this triggers the second phase
 * 4. **During the external call in Transaction 2**: The malicious contract can re-enter and call other owner-only functions while the ownership transfer is still in progress
 * 5. **State inconsistency**: The malicious contract can manipulate contract state while ownership is being transferred
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability cannot be exploited in a single transaction because the two-phase process requires separate calls
 * - The pendingOwners mapping state persists between transactions, enabling the stateful exploitation
 * - The external calls in both phases create reentrancy points, but the real vulnerability emerges from the accumulated state across multiple transactions
 * - An attacker needs to first establish pending status, then exploit the confirmation phase in subsequent transactions
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
        ) public {
        balanceOf[msg.sender] = 30000000000000000000000000;              // Give the creator all initial tokens
        totalSupply = 30000000000000000000000000;                        // Update total supply
        name = "CJZVIP";                                   // Set the name for display purposes
        symbol = "CZ";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }


    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

	
	// transfer balance to owner
	function withdrawEther(uint256 amount)onlyOwner public {
		owner.transfer(amount);
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwners;
    address public proposedOwner;
    
    function MakeOver(address _to) public onlyOwner{
        // First transaction: Propose new owner and mark as pending
        if (!pendingOwners[_to]) {
            pendingOwners[_to] = true;
            proposedOwner = _to;
            
            // Notify the proposed owner via external call (reentrancy point)
            uint extcodesize1;
            assembly { extcodesize1 := extcodesize(_to) }
            if (extcodesize1 > 0) {
                _to.call(bytes4(keccak256("onOwnershipProposed()")));
                // Continue execution regardless of call result
            }
            return;
        }
        
        // Second transaction: If already pending, complete the transfer
        if (pendingOwners[_to] && _to == proposedOwner) {
            // External call to notify of ownership confirmation (reentrancy point)
            uint extcodesize2;
            assembly { extcodesize2 := extcodesize(_to) }
            if (extcodesize2 > 0) {
                _to.call(bytes4(keccak256("onOwnershipConfirmed()")));
                // Continue execution regardless of call result
            }
            
            // State change happens after external call - classic reentrancy vulnerability
            owner = _to;
            pendingOwners[_to] = false;
            proposedOwner = address(0);
        }
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	// can accept ether
	function () public payable {
    }
}
