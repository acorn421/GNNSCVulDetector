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
 * Introduced a **STATEFUL, MULTI-TRANSACTION** reentrancy vulnerability by adding an external call to the recipient contract BEFORE updating the allowance state. This creates a classic CEI (Checks-Effects-Interactions) pattern violation.
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Update**: Inserted `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)` before the allowance modification
 * 2. **State Update Delayed**: The `allowance[_from][msg.sender] -= _value` now occurs AFTER the external call
 * 3. **Maintained Function Signature**: Preserved all original parameters and return values
 * 4. **Preserved Core Logic**: All original functionality remains intact
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker gets approval from victim for X tokens
 * - Attacker deploys malicious contract as recipient (_to address)
 * 
 * **Transaction 2 (Initial Attack)**:
 * - Attacker calls transferFrom(victim, malicious_contract, X)
 * - External call triggers malicious_contract.onTokenReceived()
 * - CRITICAL: allowance[victim][attacker] is still X (not decremented yet)
 * 
 * **Transaction 3 (Reentrancy)**:
 * - During the external call, malicious contract calls transferFrom again
 * - Since allowance hasn't been decremented, require() passes
 * - Second external call triggers, allowance still unchanged
 * - This can continue until gas limit or balance exhaustion
 * 
 * **Transaction 4+ (Continued Exploitation)**:
 * - Each reentrant call creates a new transaction context
 * - Attacker can drain multiple times the approved amount
 * - State persistence between transactions enables the attack
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Attacker needs to first obtain approval (separate transaction)
 * 2. **Persistent State Vulnerability**: The allowance state persists between calls, enabling multiple drains
 * 3. **Cross-Transaction Reentrancy**: Each reentrant call creates new transaction contexts
 * 4. **Gradual Exploitation**: Attacker can incrementally drain more than approved amount across multiple transactions
 * 
 * **Stateful Nature:**
 * - allowance mapping persists between transactions
 * - Each transaction can modify allowance state
 * - Vulnerability requires building up allowance state before exploitation
 * - Attack effectiveness increases with accumulated allowances from multiple token holders
 * 
 * This vulnerability requires sophisticated multi-transaction orchestration and cannot be exploited in a single atomic transaction, making it a realistic representation of complex reentrancy attacks seen in production DeFi protocols.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to recipient before state updates (vulnerable pattern)
        if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)) {
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