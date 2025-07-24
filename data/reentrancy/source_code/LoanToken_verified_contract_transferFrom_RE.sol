/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a window where the recipient can re-enter the transferFrom function during the callback with the allowance still at its original value.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the recipient address using `_to.call()` with a callback function signature `onTokenReceived(address,address,address,uint256)`
 * 2. Positioned this call BEFORE the allowance state update (`allowance[_from][msg.sender] -= _value;`)
 * 3. The callback provides parameters about the transfer, allowing the recipient to know the transfer details
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * 2. **Reentrancy Callback**: The malicious contract's `onTokenReceived()` function is called before allowance is decremented
 * 3. **Reentrant Call**: Within the callback, the malicious contract calls `transferFrom()` again with the same parameters
 * 4. **State Exploitation**: Since allowance hasn't been decremented yet, the second call passes the allowance check
 * 5. **Transaction 2**: The second transferFrom call completes, transferring tokens again
 * 6. **State Completion**: Original transaction completes, finally decrementing allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger a callback in a separate contract
 * - The malicious contract needs to be deployed and configured in a prior transaction
 * - The attack requires coordination between the initial transferFrom call and the reentrant callback
 * - The allowance state must be set up through previous approve() transactions
 * - The accumulated effect across multiple reentrant calls creates the exploitation window
 * 
 * This creates a realistic stateful reentrancy vulnerability where an attacker can drain more tokens than their allowance permits by exploiting the time gap between the external call and state update.
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
	function transferOwnership(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		owner = newOwner;
		}
	}
	
	function kill() onlyOwner public{
		selfdestruct(owner);
	}
}

//Announcement of an interface for recipient approving
interface tokenRecipient { 
	function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData)public; 
}


contract LoanToken is Ownable{
	
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
    function LoanToken (
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state changes - creates reentrancy opportunity
        if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
            // Callback succeeded, continue with transfer
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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