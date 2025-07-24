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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner before updating the owner state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added an external call to `newOwner.call()` to notify the new owner about the transfer
 * 2. This call happens BEFORE the state update (`owner = newOwner`)
 * 3. The call uses low-level `.call()` which allows reentrancy
 * 4. Added a require statement to ensure the notification succeeds
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls transferOwnership with a malicious contract address
 * 2. **During callback**: The malicious contract's fallback function is triggered before owner state is updated
 * 3. **Reentrant call**: The malicious contract can call other functions that still recognize the original owner
 * 4. **State manipulation**: The attacker can modify contract state while ownership is in transition
 * 5. **Transaction 2+**: After the initial transfer completes, the attacker can exploit the inconsistent state
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability creates a temporary state inconsistency during the ownership transfer
 * - The attacker needs to first establish the ownership transfer (Transaction 1)
 * - Then exploit the reentrant callback to manipulate state while owner validation is inconsistent
 * - Finally, use subsequent transactions to complete the exploit after the ownership has been transferred
 * - The exploit cannot be completed atomically because it depends on the persistent state changes from the ownership transfer
 * 
 * **Realistic Scenario:**
 * This appears as a legitimate "notification" feature for smart contracts that need to know when they become owners, but creates a critical reentrancy vulnerability during the state transition period.
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
		@newOwner: address of newOwner
	*/
	function transferOwnership(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		// Notify the new owner about the ownership transfer
            // In Solidity 0.4.x, address does not have a .code property.
            // Use extcodesize to check if the address is a contract.
		uint size;
		assembly { size := extcodesize(newOwner) }
		if (size > 0) {
			(bool success, ) = newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", owner));
			require(success);
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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


contract AAAToken is Ownable{
	
	//===================public variables definition start==================
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
	//===================public variables definition end==================

	
	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);
	//===================events definition end==================
	
	
	//===================Contract Initialization Sequence Definition start===================
    function AAAToken () public {
		decimals=10;
		totalSupply = 21000000000 * 10 ** uint256(decimals);
        balanceOf[owner] = totalSupply;
        name = "App Alliance Association";
        symbol = "AAA";
        
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
        require(_value <= allowance[_from][msg.sender]); //Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
	/*
	* Funtion: Approve usable amount for an account
	* Type:Public
	* Parameters:
		@_spender: address of spender's account
		@_value: approve amount
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
		@_value: approve amount
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
   //===================Contract behavior & funtions definition end===================
}
