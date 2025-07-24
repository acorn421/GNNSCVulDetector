/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection introduces a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding a notification mechanism during ownership transfer. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: `pendingOwnershipTransfers` mapping and `pendingOwner` address to track transfer state
 * 2. **Introduced External Call**: Added `newOwner.call()` to notify the new owner before updating the owner state
 * 3. **Violates Checks-Effects-Interactions**: The external call occurs before the state update, creating a reentrancy window
 * 4. **Created Stateful Conditions**: The pending state persists between transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Current owner calls `transferOwnership(maliciousContract)`
 *    - `pendingOwnershipTransfers[maliciousContract] = true`
 *    - `pendingOwner = maliciousContract`
 *    - External call triggers `maliciousContract.onOwnershipTransferred()`
 *    - Malicious contract can now check `pendingOwnershipTransfers[address(this)] == true`
 * 
 * 2. **Transaction 2**: During the external call, malicious contract re-enters:
 *    - Calls `transferOwnership(anotherAddress)` while still in pending state
 *    - The `onlyOwner` modifier still sees the original owner (not updated yet)
 *    - Can manipulate the ownership transfer process or extract value
 * 
 * 3. **Transaction 3+**: Additional reentrant calls can:
 *    - Transfer ownership multiple times
 *    - Access functions that depend on ownership state
 *    - Exploit the window between external call and state update
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent state of `pendingOwnershipTransfers` and `pendingOwner`
 * - The external call creates a window where the contract is in an inconsistent state across multiple call frames
 * - The exploit requires the malicious contract to have been deployed and registered in the pending state first
 * - The reentrancy attack spans multiple transactions because the external call can trigger complex callback chains
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world ownership transfer mechanisms that include notification callbacks, making it a realistic vulnerability that could appear in production code while maintaining the original function's intended behavior.
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
	address public owner;
	mapping(address => bool) public pendingOwnershipTransfers;
	address public pendingOwner;

	function Ownable() public 
	{
		owner = msg.sender;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}
	/*
	* Funtion: Transfer owner's authority 
	* Type:Public and onlyOwner
	* Parameters:
		@newOwner:	address of newOwner
	*/
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	function transferOwnership(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
			// Mark transfer as pending
			pendingOwnershipTransfers[newOwner] = true;
			pendingOwner = newOwner;
			
			// External call to notify new owner before state change - REENTRANCY VECTOR
			uint codeLength;
			assembly {
				codeLength := extcodesize(newOwner)
			}
			if (codeLength > 0) {
				newOwner.call(
					abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, newOwner)
				);
			}
			// State change after external call - classic reentrancy vulnerability
			owner = newOwner;
			// Clean up pending state
			pendingOwnershipTransfers[newOwner] = false;
			pendingOwner = address(0);
		}
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function kill() onlyOwner public{
		selfdestruct(owner);
	}
}

//Announcement of an interface for recipient approving
interface tokenRecipient { 
	function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData)public; 
}


contract CtripToken is Ownable{
	
	//===================public variables definition start==================
    string public name; //Name of your Token
    string public symbol; //Symbol of your Token
    uint8 public decimals = 18; //Decimals of your Token
    uint256 public totalSupply; //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf; //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance; //Announce the dictionary of account's available balance
	//===================public variables definition end==================

	
	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value); //Event on blockchain which notify client
	//===================events definition end==================
	
	
	//===================Contract Initialization Sequence Definition start===================
    function CtripToken(
            uint256 initialSupply,
            string tokenName,
            string tokenSymbol
        ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        
    }
	//===================Contract Initialization Sequence definition end===================
	
	//===================Contract behavior & funtions definition start===================
	
	/*
	* Funtion: Transfer funtions
	* Type:Internal
	* Parameters:
			@_from:	address of sender's account
			@_to:	address of recipient's account
			@_value:transaction amount
	*/
    function _transfer(address _from, address _to, uint _value) internal {
		//Fault-tolerant processing
		require(_to != 0x0); //
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        //Execute transaction
		uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
		
		//Verify transaction
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
	
	
	/*
	* Funtion: Transfer tokens
	* Type:Public
	* Parameters:
			@_to:	address of recipient's account
			@_value:transaction amount
	*/
    function transfer(address _to, uint256 _value) public {
		
        _transfer(msg.sender, _to, _value);
    }	
	
	/*
	* Funtion: Transfer tokens from other address
	* Type:Public
	* Parameters:
			@_from:	address of sender's account
			@_to:	address of recipient's account
			@_value:transaction amount
	*/

    function transferFrom(address _from, address _to, uint256 _value) public 
	returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);   //Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
	/*
	* Funtion: Approve usable amount for an account
	* Type:Public
	* Parameters:
			@_spender:	address of spender's account
			@_value:	approve amount
	*/
    function approve(address _spender, uint256 _value) public 
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
        }

	/*
	* Funtion: Approve usable amount for other address and then notify the contract
	* Type:Public
	* Parameters:
			@_spender:	address of other account
			@_value:	approve amount
			@_extraData:additional information to send to the approved contract
	*/
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public 
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
    /*
	* Funtion: Transfer owner's authority and account balance
	* Type:Public and onlyOwner
	* Parameters:
			@newOwner:	address of newOwner
	*/
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		    _transfer(owner,newOwner,balanceOf[owner]);
		    owner = newOwner;
		}
	}
   //===================Contract behavior & funtions definition end===================
}
