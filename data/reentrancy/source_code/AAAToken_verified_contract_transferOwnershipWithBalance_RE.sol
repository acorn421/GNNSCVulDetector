/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnershipWithBalance
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
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. SPECIFIC CHANGES MADE:**
 * - Added an external call to `newOwner.call()` before state updates
 * - The call invokes `onOwnershipTransfer(address,uint256)` callback on the new owner contract
 * - Cached `balanceOf[owner]` in a local variable but state updates occur after the external call
 * - The external call happens before both balance transfer and ownership change
 * 
 * **2. MULTI-TRANSACTION EXPLOITATION MECHANISM:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys a malicious contract that implements `onOwnershipTransfer`
 * - The malicious contract's callback function is designed to re-enter the token contract
 * 
 * **Transaction 2 - Trigger Vulnerability:**
 * - Current owner calls `transferOwnershipWithBalance(maliciousContract)`
 * - During the external call, the malicious contract's `onOwnershipTransfer` callback executes
 * - At this point, `owner` is still the original owner, but the callback can manipulate state
 * 
 * **Transaction 3+ - Exploitation:**
 * - The malicious callback can call other token functions (transfer, approve, etc.) 
 * - Since `owner` hasn't changed yet, the original owner's privileges are still active
 * - The callback can drain tokens, manipulate allowances, or call `transferOwnershipWithBalance` again
 * - Multiple reentrant calls can occur before the original ownership transfer completes
 * 
 * **3. WHY MULTI-TRANSACTION EXPLOITATION IS REQUIRED:**
 * - **State Accumulation**: The vulnerability depends on the inconsistent state where balance transfer is initiated but ownership hasn't changed
 * - **Persistent State Window**: The external call creates a window where the contract is in an inconsistent state across multiple call frames
 * - **Cross-Transaction Attack Vector**: The attacker needs to first deploy the malicious contract, then trigger the vulnerability, then exploit the inconsistent state
 * - **Stateful Reentrancy**: Unlike simple reentrancy, this requires the attacker to maintain state across multiple transactions to fully exploit the ownership transfer race condition
 * 
 * **4. REALISTIC VULNERABILITY CHARACTERISTICS:**
 * - The callback mechanism appears as a legitimate feature for notifying new owners
 * - The vulnerability follows real-world patterns seen in ownership transfer functions
 * - The code maintains the original function's behavior while introducing the security flaw
 * - The multi-transaction nature makes it harder to detect during testing but exploitable in production
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


contract AAAToken is Ownable{
	
	//===================public variables definition start==================
    string public name;															//Name of your Token
    string public symbol;														//Symbol of your Token
    uint8 public decimals;														//Decimals of your Token
    uint256 public totalSupply;													//Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;								//Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;			//Announce the dictionary of account's available balance
	//===================public variables definition end==================

	
	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);	//Event on blockchain which notify client
	//===================events definition end==================
	
	
	//===================Contract Initialization Sequence Definition start===================
    function AAAToken () public {
		decimals=10;															//Assignment of Token's decimals
		totalSupply = 21000000000 * 10 ** uint256(decimals);  				//Assignment of Token's total supply with decimals
        balanceOf[owner] = totalSupply;                						//Assignment of Token's creator initial tokens
        name = "App Alliance Association";                                   					//Set the name of Token
        symbol = "AAA";                               						//Set the symbol of  Token
        
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	if (newOwner != address(0)) {
	    uint256 ownerBalance = balanceOf[owner];
	    
	    // Notify new owner about incoming ownership transfer with balance
	    if (newOwner.call(bytes4(keccak256("onOwnershipTransfer(address,uint256)")), owner, ownerBalance)) {
	        // Transfer continues if callback succeeds
	    }
	    
	    // Transfer balance to new owner
	    _transfer(owner, newOwner, ownerBalance);
	    
	    // Transfer ownership after balance transfer
	    owner = newOwner;
	}
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
   //===================Contract behavior & funtions definition end===================
}