/*
 * ===== SmartInject Injection Details =====
 * Function      : timeBasedTransferLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that is stateful and requires multiple transactions to exploit. The vulnerability works as follows:
 * 
 * 1. **First Transaction**: User calls lockTransfers() to set a transfer lock with transferLockTime[msg.sender] = now + _lockDuration
 * 2. **State Persistence**: The lock time is stored in the transferLockTime mapping and persists between transactions
 * 3. **Second Transaction**: User calls emergencyUnlock() which contains a vulnerable timestamp condition (now % 60 < 30)
 * 4. **Exploitation**: A malicious miner can manipulate the block timestamp to ensure the condition is met, allowing premature unlock
 * 
 * The vulnerability is stateful because:
 * - The lock state persists in transferLockTime mapping between transactions
 * - The vulnerability cannot be exploited in a single transaction
 * - It requires the sequence: lockTransfers() → wait/manipulate timestamp → emergencyUnlock()
 * - The exploit depends on accumulated state changes across multiple blocks/transactions
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
	address public owner;                            //owner's address

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
interface tokenRecipient { 
	function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData)public; 
}


contract AAAToken is Ownable{
	
	//===================public variables definition start==================
    string public name;                                                        //Name of your Token
    string public symbol;                                                        //Symbol of your Token
    uint8 public decimals;                                                        //Decimals of your Token
    uint256 public totalSupply;                                                    //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;                                //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;            //Announce the dictionary of account's available balance

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    //===================Time-based transfer lock functionality start===================
    mapping (address => uint256) transferLockTime;                      //Timestamp when transfer lock expires
    uint256 public lockDuration = 24 hours;                                   //Default lock duration
    
    /*
    *   Function: Lock transfers for a specific duration
    *   Type: Public
    *   Parameters:
            @_lockDuration: duration in seconds to lock transfers
    */
    function lockTransfers(uint256 _lockDuration) public {
        require(_lockDuration > 0);
        transferLockTime[msg.sender] = now + _lockDuration;
    }
    
    /*
    *   Function: Enable early unlock based on timestamp manipulation
    *   Type: Public 
    *   Parameters: None
    */
    function emergencyUnlock() public {
        // Vulnerable: Uses block.timestamp (now) which can be manipulated by miners
        // The vulnerability requires multiple transactions:
        // 1. First call lockTransfers() to set a lock
        // 2. Wait for a favorable timestamp condition
        // 3. Call emergencyUnlock() when timestamp conditions are met
        require(transferLockTime[msg.sender] > 0);
        
        // Vulnerable condition: allows unlock if current time appears to be in a "safe window"
        // Miners can manipulate timestamp to make this condition true
        if (now % 60 < 30) {  // Vulnerable: timestamp dependence
            transferLockTime[msg.sender] = 0;
        }
    }
    
    /*
    *   Function: Check if transfers are currently locked
    *   Type: Public view
    *   Parameters: 
            @_account: address to check lock status
    */
    function isTransferLocked(address _account) public view returns (bool) {
        return transferLockTime[_account] > now;
    }
    
    //===================Time-based transfer lock functionality end===================
    // === END FALLBACK INJECTION ===

    //===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);    //Event on blockchain which notify client
    //===================events definition end==================
    
    //===================Contract Initialization Sequence Definition start===================
    function AAAToken () public {
        decimals=10;                                                            //Assignment of Token's decimals
        totalSupply = 21000000000 * 10 ** uint256(decimals);                     //Assignment of Token's total supply with decimals
        balanceOf[owner] = totalSupply;                                         //Assignment of Token's creator initial tokens
        name = "App Alliance Association";                                      //Set the name of Token
        symbol = "AAA";                                        //Set the symbol of  Token
    }
    //===================Contract Initialization Sequence definition end===================
    
    //===================Contract behavior & funtions definition start===================
    
    /*
    *   Funtion: Transfer funtions
    *   Type:Internal
    *   Parameters:
            @_from: address of sender's account
            @_to: address of recipient's account
            @_value:transaction amount
    */
    function _transfer(address _from, address _to, uint _value) internal {
        //Fault-tolerant processing
        require(_to != 0x0);                        //
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
    *   Funtion: Transfer tokens
    *   Type:Public
    *   Parameters:
            @_to: address of recipient's account
            @_value:transaction amount
    */
    function transfer(address _to, uint256 _value) public {
        
        _transfer(msg.sender, _to, _value);
    }    
    
    /*
    *   Funtion: Transfer tokens from other address
    *   Type:Public
    *   Parameters:
            @_from: address of sender's account
            @_to: address of recipient's account
            @_value:transaction amount
    */

    function transferFrom(address _from, address _to, uint256 _value) public 
    returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);                         //Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    /*
    *   Funtion: Approve usable amount for an account
    *   Type:Public
    *   Parameters:
            @_spender: address of spender's account
            @_value:    approve amount
    */
    function approve(address _spender, uint256 _value) public 
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
        }

    /*
    *   Funtion: Approve usable amount for other address and then notify the contract
    *   Type:Public
    *   Parameters:
            @_spender: address of other account
            @_value:    approve amount
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
    *   Funtion: Transfer owner's authority and account balance
    *   Type:Public and onlyOwner
    *   Parameters:
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
