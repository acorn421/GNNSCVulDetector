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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `pendingOwnership` and `ownershipNonce` mappings to track ownership transfer state across transactions.
 * 
 * 2. **External Call Before State Update**: Added `newOwner.call()` to notify the new owner BEFORE updating the owner state variable. This creates a reentrancy window where the original owner is still in control.
 * 
 * 3. **Persistent State Tracking**: The `pendingOwnership` mapping persists between transactions, allowing attackers to exploit accumulated state changes.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` 
 * - `pendingOwnership[maliciousContract] = true`
 * - External call to `maliciousContract.onOwnershipTransferred()`
 * - During this call, `maliciousContract` can re-enter `transferOwnership()` since `owner` hasn't changed yet
 * - Multiple ownership transfers can be initiated in nested calls
 * - State accumulates in `pendingOwnership` mapping
 * 
 * **Transaction 2**: Attacker exploits the corrupted state
 * - Multiple addresses may have `pendingOwnership[address] = true`
 * - Attacker can call other functions that check `pendingOwnership` status
 * - Can potentially claim ownership through different code paths
 * 
 * **Transaction 3**: Final exploitation
 * - Use accumulated state from previous transactions
 * - Exploit timing differences in `ownershipNonce` values
 * - Complete the ownership takeover using the multi-transaction state corruption
 * 
 * **Why Multi-Transaction Required:**
 * - State corruption builds up across multiple function calls
 * - `pendingOwnership` mapping retains state between transactions
 * - `ownershipNonce` creates sequence dependencies
 * - Full exploitation requires leveraging accumulated state changes from previous transactions
 * - Single transaction cannot exploit the full vulnerability potential
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
	address public owner;														//owner's address

	function Ownable() public 
	{
		owner = msg.sender;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}
	/*
	*	Funtion: Transfer owner's authority 
	*	Type:Public and onlyOwner
	*	Parameters:
			@newOwner:	address of newOwner
	*/
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingOwnership;
mapping(address => uint256) public ownershipNonce;

function transferOwnership(address newOwner) onlyOwner public{
	if (newOwner != address(0)) {
		// Mark pending ownership transfer
		pendingOwnership[newOwner] = true;
		ownershipNonce[newOwner] = block.number;
		
		// Notify new owner before state update - VULNERABILITY
		if (newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", owner))) {
			// Only update owner after successful notification
			owner = newOwner;
			pendingOwnership[newOwner] = false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		}
	}
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
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


contract FloodDragon is Ownable{
	
	//===================public variables definition start==================
    string public name;															//Name of your Token
    string public symbol;														//Symbol of your Token
    uint8 public decimals = 18;														//Decimals of your Token
    uint256 public totalSupply;													//Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;								//Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;			//Announce the dictionary of account's available balance
	//===================public variables definition end==================

	
	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);	//Event on blockchain which notify client
	//===================events definition end==================
	
	
	//===================Contract Initialization Sequence Definition start===================
    function FloodDragon (
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
	*	Funtion: Transfer funtions
	*	Type:Internal
	*	Parameters:
			@_from:	address of sender's account
			@_to:	address of recipient's account
			@_value:transaction amount
	*/
    function _transfer(address _from, address _to, uint _value) internal {
		//Fault-tolerant processing
		require(_to != 0x0);						//
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
	*	Funtion: Transfer tokens
	*	Type:Public
	*	Parameters:
			@_to:	address of recipient's account
			@_value:transaction amount
	*/
    function transfer(address _to, uint256 _value) public {
		
        _transfer(msg.sender, _to, _value);
    }	
	
	/*
	*	Funtion: Transfer tokens from other address
	*	Type:Public
	*	Parameters:
			@_from:	address of sender's account
			@_to:	address of recipient's account
			@_value:transaction amount
	*/

    function transferFrom(address _from, address _to, uint256 _value) public 
	returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     					//Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
	/*
	*	Funtion: Approve usable amount for an account
	*	Type:Public
	*	Parameters:
			@_spender:	address of spender's account
			@_value:	approve amount
	*/
    function approve(address _spender, uint256 _value) public 
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
        }

	/*
	*	Funtion: Approve usable amount for other address and then notify the contract
	*	Type:Public
	*	Parameters:
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
	*	Funtion: Transfer owner's authority and account balance
	*	Type:Public and onlyOwner
	*	Parameters:
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