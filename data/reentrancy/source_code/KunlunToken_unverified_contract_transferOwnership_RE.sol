/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added**: Added `pendingOwnershipTransfers` mapping and `pendingOwner` variable to track ownership transition state across transactions.
 * 
 * 2. **External Call Before State Update**: Added an external call to the previous owner (`owner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", newOwner))`) before updating the owner state, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Legitimate owner calls `transferOwnership(attackerContract)` 
 *    - **Reentrancy**: The external call to previous owner allows attacker's contract to re-enter
 *    - **Transaction 2**: During reentrancy, attacker can call `transferOwnership` again while `pendingOwner` is set but `owner` hasn't been updated yet
 *    - **Transaction 3**: Attacker exploits the intermediate state where ownership is transitioning
 * 
 * 4. **Stateful Nature**: The vulnerability relies on the persistent state of `pendingOwner` and `pendingOwnershipTransfers` mapping that exists between transactions and can be manipulated during the ownership transition window.
 * 
 * 5. **Realistic Pattern**: The notification mechanism is a common feature in ownership transfer systems, making this vulnerability realistic and subtle.
 * 
 * **Multi-Transaction Exploitation Sequence**:
 * - The attacker needs to first become a legitimate owner or control the previous owner contract
 * - Then trigger the ownership transfer which creates a window of vulnerability
 * - During the external call, re-enter to manipulate ownership state
 * - The vulnerability cannot be exploited in a single transaction due to the sequential nature of the ownership transition and the need for external call interaction.
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
mapping(address => bool) public pendingOwnershipTransfers;
address public pendingOwner;

function transferOwnership(address newOwner) onlyOwner public{
	if (newOwner != address(0)) {
		// Set pending ownership state
		pendingOwner = newOwner;
		pendingOwnershipTransfers[newOwner] = true;
		
		// Notify previous owner with external call before state change
		if (owner != address(0)) {
			// External call to previous owner - potential reentrancy point
			(bool success, ) = owner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", newOwner));
			// Continue regardless of call success
		}
		
		// Update owner state after external call (violates CEI pattern)
		owner = newOwner;
		
		// Clear pending state
		pendingOwner = address(0);
		pendingOwnershipTransfers[newOwner] = false;
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


contract KunlunToken is Ownable{
	
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
    function KunlunToken (
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