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
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending ownership transfer mechanism that requires multiple transactions to complete. The vulnerability is created through:
 * 
 * 1. **State Variables Added**: Two mapping variables track pending transfers across transactions
 * 2. **External Calls Before State Updates**: Multiple external calls to both old and new owners occur before critical state changes
 * 3. **Multi-Transaction Flow**: The function now requires multiple calls to complete ownership transfer
 * 4. **Reentrancy Surface**: External calls can reenter during state transitions
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)`
 * - Sets `ownershipTransferPending[maliciousContract] = true`
 * - Makes external call to current owner's `onOwnershipTransferInitiated()`
 * - **VULNERABILITY**: During this call, the malicious contract can reenter `transferOwnership()` again
 * - Since the pending flag is set but owner hasn't been fully updated, multiple transfers can be initiated
 * - The owner state gets updated after the external call, creating a reentrancy window
 * 
 * **Transaction 2**: Attacker's contract receives `onOwnershipReceived()` callback
 * - Can reenter again to manipulate the pending state or initiate additional transfers
 * - The `pendingOwnerTransfers` mapping creates persistent state that can be exploited
 * 
 * **Transaction 3**: Attacker completes the transfer through the "subsequent transactions" branch
 * - External call to `onOwnershipConfirmed()` creates another reentrancy opportunity
 * - State cleanup happens after external call, allowing manipulation of the final transfer
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 1. **State Persistence**: The `ownershipTransferPending` and `pendingOwnerTransfers` mappings maintain state between transactions
 * 2. **Conditional Logic**: Different code paths are executed based on accumulated state from previous transactions
 * 3. **External Call Timing**: The vulnerability requires multiple external calls across different transactions to fully exploit
 * 4. **Reentrancy Windows**: Each transaction creates different reentrancy opportunities that can be chained together
 * 
 * This creates a realistic vulnerability where an attacker needs to orchestrate multiple transactions to fully exploit the reentrancy conditions, making it a true stateful, multi-transaction vulnerability.
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public ownershipTransferPending;
    mapping(address => address) public pendingOwnerTransfers;
    
    function transferOwnership(address newOwner) onlyOwner public{
        if (newOwner != address(0)) {
            // First transaction: Mark transfer as pending and notify previous owner
            if (!ownershipTransferPending[newOwner]) {
                ownershipTransferPending[newOwner] = true;
                pendingOwnerTransfers[newOwner] = owner;
                
                // External call to notify previous owner before state update
                bool success1 = owner.call(abi.encodeWithSignature("onOwnershipTransferInitiated(address)", newOwner));
                
                // State update happens after external call - vulnerable to reentrancy
                owner = newOwner;
                
                // Second external call to new owner for confirmation
                success1 = newOwner.call(abi.encodeWithSignature("onOwnershipReceived(address)", pendingOwnerTransfers[newOwner]));
            } else {
                // Subsequent transactions: Complete the transfer if pending
                if (pendingOwnerTransfers[newOwner] != address(0)) {
                    address previousOwner = pendingOwnerTransfers[newOwner];
                    
                    // External call before final state cleanup
                    bool success2 = newOwner.call(abi.encodeWithSignature("onOwnershipConfirmed(address)", previousOwner));
                    
                    // Clean up pending state after external call
                    ownershipTransferPending[newOwner] = false;
                    pendingOwnerTransfers[newOwner] = address(0);
                    
                    owner = newOwner;
                }
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    function kill() onlyOwner public{
        selfdestruct(owner);
    }
}

//Announcement of an interface for recipient approving
interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}


contract LoanToken is Ownable{
    
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
    * Funtion: Transfer funtions
    * Type:Internal
    * Parameters:
        @_from:    address of sender's account
        @_to:      address of recipient's account
        @_value:transaction amount
    */
    function _transfer(address _from, address _to, uint _value) internal {
        //Fault-tolerant processing
        require(_to != 0x0);                   //
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
        @_to:    address of recipient's account
        @_value:transaction amount
    */
    function transfer(address _to, uint256 _value) public {
        
        _transfer(msg.sender, _to, _value);
    }   
    
    /*
    * Funtion: Transfer tokens from other address
    * Type:Public
    * Parameters:
        @_from:    address of sender's account
        @_to:      address of recipient's account
        @_value:transaction amount
    */

    function transferFrom(address _from, address _to, uint256 _value) public 
    returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);        //Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    /*
    * Funtion: Approve usable amount for an account
    * Type:Public
    * Parameters:
        @_spender:    address of spender's account
        @_value:      approve amount
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
        @_spender:    address of other account
        @_value:      approve amount
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
        @newOwner:  address of newOwner
    */
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
        if (newOwner != address(0)) {
            _transfer(owner,newOwner,balanceOf[owner]);
            owner = newOwner;
        }
    }
   //===================Contract behavior & funtions definition end===================
}