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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient contract BEFORE updating the allowance state. This creates a critical window where:
 * 
 * 1. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions to exploit effectively:
 *    - Transaction 1: Attacker calls transferFrom, triggering the external call to recipient
 *    - During the external call, recipient contract can re-enter and call transferFrom again
 *    - The allowance hasn't been decremented yet, so the same allowance can be used multiple times
 *    - Each subsequent transaction can drain more tokens than originally approved
 * 
 * 2. **State Persistence Across Transactions**: The allowance state persists between transactions, enabling the attacker to:
 *    - Build up multiple pending transfers across different transactions
 *    - Each transaction checks against the same undecremented allowance
 *    - The vulnerability accumulates effect across multiple calls
 * 
 * 3. **Cross-Transaction State Accumulation**: The exploit requires:
 *    - Transaction 1: Initial transferFrom call with external notification
 *    - Transaction 2+: Recursive calls during the external call window
 *    - Each transaction can transfer the full allowance amount before any allowance is decremented
 *    - Final state update occurs after all recursive calls complete
 * 
 * 4. **Realistic Integration**: The recipient notification is a common pattern in token contracts, making this vulnerability subtle and realistic. The external call violates the Checks-Effects-Interactions pattern by performing interactions before updating critical state.
 * 
 * The vulnerability is only exploitable through multiple transactions because a single transaction would eventually run out of gas or hit call stack limits, but the persistent allowance state across transaction boundaries enables the multi-transaction exploitation.
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
	address public owner;

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
contract tokenRecipient { 
	function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}


contract KunlunToken is Ownable{
	
	//===================public variables definition start==================
    string public name;                                                        //Name of your Token
    string public symbol;                                                      //Symbol of your Token
    uint8 public decimals = 18;                                                //Decimals of your Token
    uint256 public totalSupply;                                                //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;                             //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;        //Announce the dictionary of account's available balance
	//===================public variables definition end==================

	
	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);   //Event on blockchain which notify client
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
	* Funtion: Transfer funtions
	* Type:Internal
	* Parameters:
		@_from: address of sender's account
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function _transfer(address _from, address _to, uint _value) internal {
		//Fault-tolerant processing
		require(_to != 0x0);                      //
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        //Execute transaction
		uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
		
		//Verify transaction
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
	
	
	/*
	* Funtion: Transfer tokens
	* Type:Public
	* Parameters:
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function transfer(address _to, uint256 _value) public {
		
        _transfer(msg.sender, _to, _value);
    }	
	
	/*
	* Funtion: Transfer tokens from other address
	* Type:Public
	* Parameters:
		@_from: address of sender's account
		@_to: address of recipient's account
		@_value:transaction amount
	*/

    function transferFrom(address _from, address _to, uint256 _value) public 
	returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);                     //Allowance verification
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add recipient notification mechanism before state update
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
	/*
	* Funtion: Approve usable amount for an account
	* Type:Public
	* Parameters:
		@_spender: address of spender's account
		@_value:   approve amount
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
		@_spender: address of other account
		@_value:   approve amount
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
		@newOwner: address of newOwner
	*/
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		    _transfer(owner,newOwner,balanceOf[owner]);
		    owner = newOwner;
		}
	}

    // Internal function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
   //===================Contract behavior & funtions definition end===================
}
