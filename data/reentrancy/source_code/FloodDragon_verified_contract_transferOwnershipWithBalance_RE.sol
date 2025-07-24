/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnershipWithBalance
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before the ownership state is updated. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner` using low-level `call()` to invoke `onOwnershipTransferred(address,uint256)`
 * 2. The call passes the current owner and the new owner's balance as parameters
 * 3. The external call occurs AFTER the balance transfer but BEFORE the ownership update (`owner = newOwner`)
 * 4. Added a contract size check to only make the call if the address is a contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * **Transaction 1 (Setup):** Attacker deploys a malicious contract that implements `onOwnershipTransferred()` callback
 * **Transaction 2 (Trigger):** Current owner calls `transferOwnershipWithBalance()` with the malicious contract address
 * **During Callback:** The malicious contract's `onOwnershipTransferred()` is called while:
 * - Balance has been transferred to the malicious contract
 * - BUT ownership is still with the original owner (vulnerable state window)
 * - The malicious contract can now call other privileged functions using the fact that `owner` hasn't changed yet
 * **Transaction 3+ (Exploit):** The malicious contract can exploit the inconsistent state by calling other owner-only functions while having both the tokens and temporary access to owner privileges
 * 
 * **Why Multiple Transactions Are Required:**
 * - **State Accumulation:** The vulnerability requires the attacker to first deploy and position a malicious contract (Transaction 1)
 * - **Sequence Dependency:** The exploit only works when the ownership transfer is initiated by the legitimate owner (Transaction 2)
 * - **Persistent State Window:** The vulnerability creates a persistent state inconsistency where tokens are transferred but ownership rights remain with the original owner until the callback completes
 * - **Cannot Be Atomic:** The exploit requires the external call to interrupt the ownership transfer process, which cannot happen in a single transaction from the attacker's perspective
 * 
 * This creates a realistic reentrancy vulnerability that violates the Checks-Effects-Interactions pattern and requires multiple transactions to set up and exploit effectively.
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
    address public owner;                                                        //owner's address

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
            @newOwner:  address of newOwner
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
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}


contract FloodDragon is Ownable{
    
    //===================public variables definition start==================
    string public name;                                                           //Name of your Token
    string public symbol;                                                         //Symbol of your Token
    uint8 public decimals = 18;                                                       //Decimals of your Token
    uint256 public totalSupply;                                                 //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;                               //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;          //Announce the dictionary of account's available balance
    //===================public variables definition end==================

    
    //===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value); //Event on blockchain which notify client
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
        require(_value <= allowance[_from][msg.sender]);                          //Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    /*
    *   Funtion: Approve usable amount for an account
    *   Type:Public
    *   Parameters:
            @_spender:   address of spender's account
            @_value: approve amount
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
    *   Funtion: Transfer owner's authority and account balance
    *   Type:Public and onlyOwner
    *   Parameters:
            @newOwner:  address of newOwner
    */
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
        if (newOwner != address(0)) {
            _transfer(owner,newOwner,balanceOf[owner]);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify new owner about the ownership transfer
            if (isContract(newOwner)) {
                bytes4 selector = bytes4(keccak256("onOwnershipTransferred(address,uint256)"));
                bool success = newOwner.call(selector, owner, balanceOf[newOwner]);
                require(success, "Ownership notification failed");
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            owner = newOwner;
        }
    }
    
    // Helper function to detect if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 codeLength;
        assembly { codeLength := extcodesize(_addr) }
        return codeLength > 0;
    }
   //===================Contract behavior & funtions definition end===================
}