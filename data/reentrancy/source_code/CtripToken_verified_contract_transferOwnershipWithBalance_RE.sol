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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Replaced the internal `_transfer` with manual balance updates followed by an external call to `tokenRecipient(newOwner).receiveApproval()`. This creates a reentrancy opportunity where the recipient can call back into the contract.
 * 
 * 2. **State Update After External Call**: The critical ownership transfer (`owner = newOwner`) now happens AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `transferOwnershipWithBalance(maliciousContract)`
 *    - **During reentrancy**: The malicious contract's `receiveApproval` function is called while the attacker is still the owner
 *    - **Reentrancy call**: The malicious contract calls `transferOwnershipWithBalance(attackerAddress)` again
 *    - **Transaction 2**: Since ownership hasn't been transferred yet, the attacker can transfer ownership to themselves or drain more tokens
 *    - **Result**: Multiple ownership transfers or balance manipulations across the reentrant calls
 * 
 * 4. **State Persistence Requirements**: 
 *    - The vulnerability requires the owner state to persist between the initial call and the reentrant call
 *    - Each transaction modifies the `balanceOf` mapping and `owner` state
 *    - The accumulated state changes across multiple transactions enable the exploit
 * 
 * 5. **Why Multi-Transaction**: The vulnerability cannot be exploited in a single transaction because:
 *    - The initial call must establish the external call context
 *    - The reentrant call must occur while the original transaction is still executing
 *    - The state modifications must accumulate across the call stack
 *    - The final ownership transfer depends on the state from previous calls in the sequence
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple function calls and persistent state changes to exploit, making it a true stateful, multi-transaction vulnerability.
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
    *   Funtion: Transfer owner's authority 
    *   Type:Public and onlyOwner
    *   Parameters:
            @newOwner:    address of newOwner
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


contract CtripToken is Ownable{
    
    //===================public variables definition start==================
    string public name;                                                         //Name of your Token
    string public symbol;                                                       //Symbol of your Token
    uint8 public decimals = 18;                                                     //Decimals of your Token
    uint256 public totalSupply;                                                 //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;                              //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;         //Announce the dictionary of account's available balance
    //===================public variables definition end==================

    
    //===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);    //Event on blockchain which notify client
    //===================events definition end==================
    
    
    //===================Contract Initialization Sequence Definition start===================
    function CtripToken (
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
    *   Funtion: Transfer funtions
    *   Type:Internal
    *   Parameters:
            @_from: address of sender's account
            @_to:   address of recipient's account
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
        emit Transfer(_from, _to, _value);
        
        //Verify transaction
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    
    
    /*
    *   Funtion: Transfer tokens
    *   Type:Public
    *   Parameters:
            @_to:   address of recipient's account
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
            @_to:   address of recipient's account
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
            @_spender:   address of spender's account
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
            @_spender:   address of other account
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
            @newOwner:    address of newOwner
    */
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    if (newOwner != address(0)) {
        uint256 ownerBalance = balanceOf[owner];
        
        // Transfer tokens to new owner (external call first)
        balanceOf[owner] -= ownerBalance;
        balanceOf[newOwner] += ownerBalance;
        
        // Notify recipient about the transfer (external call vulnerability)
        if (isContract(newOwner)) {
            tokenRecipient(newOwner).receiveApproval(owner, ownerBalance, this, "");
        }
        
        // Transfer ownership after external call (state update after external call)
        owner = newOwner;
        
        emit Transfer(owner, newOwner, ownerBalance);
    }
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
   //===================Contract behavior & funtions definition end===================

    // Helper function for contract detection in pre-0.5.0
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
