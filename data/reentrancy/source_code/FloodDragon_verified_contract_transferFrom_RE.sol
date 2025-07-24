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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a reentrancy window where an attacker can exploit the unchanged allowance state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract (`_to.call()`) before allowance deduction
 * 2. Call triggers `onTokenReceived` callback if recipient is a contract
 * 3. Allowance state update moved to after external call, creating reentrancy window
 * 4. Maintained original function signature and core functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker gets approval for X tokens from victim
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls transferFrom, triggering recipient callback
 * 3. **During Callback (Reentrancy)**: Malicious contract calls transferFrom again before allowance is updated
 * 4. **Transaction 3 (Repeated)**: Process repeats across multiple transactions, each exploiting the stale allowance state
 * 5. **Result**: Attacker transfers more tokens than originally approved by accumulating transfers across transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - Each reentrancy call can only exploit the current allowance state
 * - To drain significant funds, attacker needs multiple transaction cycles
 * - Gas limits prevent infinite recursion in single transaction
 * - Realistic exploitation requires building up accumulated unauthorized transfers over time
 * - State persistence between transactions enables repeated exploitation of the same allowance
 * 
 * **Stateful Nature:**
 * - `allowance` mapping persists between transactions
 * - Each transaction can modify and exploit this persistent state
 * - Accumulated effect of multiple reentrancy attacks across transactions
 * - Vulnerability depends on state not being updated before external calls
 * 
 * This creates a realistic, production-like vulnerability where the external call mechanism (common in DeFi protocols) introduces a reentrancy window that can be exploited over multiple transactions to drain more tokens than authorized.
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

contract FloodDragon is Ownable{
	
	//===================public variables definition start==================
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
	//===================public variables definition end==================

	
	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);
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
        require(_value <= allowance[_from][msg.sender]);     //Allowance verification
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // First notify recipient before state changes - creates reentrancy window
        if (isContract(_to)) {
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            _to.call(selector, _from, msg.sender, _value);
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

    // Helper function for contract code detection (for compatibility with Solidity 0.4.x)
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
   //===================Contract behavior & funtions definition end===================
}
