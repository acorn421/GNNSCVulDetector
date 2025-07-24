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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a window where malicious contracts can re-enter transferFrom with the same allowance values, enabling unauthorized transfers across multiple transactions. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Initial transferFrom call triggers external call to malicious recipient contract
 * 2. **Reentrancy Attack**: Malicious contract re-enters transferFrom before allowance is decreased
 * 3. **Transaction 2**: Second transferFrom call uses the same allowance value, bypassing intended spending limits
 * 4. **State Accumulation**: Multiple reentrant calls can drain allowances beyond authorized amounts
 * 
 * The vulnerability is stateful because it relies on the persistent allowance mapping state between transactions, and multi-transaction because the exploit requires a sequence of calls where earlier calls enable later unauthorized transfers. The external call occurs before the critical allowance update, violating the checks-effects-interactions pattern and creating a genuine reentrancy vulnerability that maintains the function's core ERC20 compatibility.
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


contract CtripToken is Ownable{
    
    //===================public variables definition start==================
    string public name;                                                            //Name of your Token
    string public symbol;                                                          //Symbol of your Token
    uint8 public decimals = 18;                                                        //Decimals of your Token
    uint256 public totalSupply;                                                    //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;                                 //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance;            //Announce the dictionary of account's available balance
    //===================public variables definition end==================

    
    //===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);   //Event on blockchain which notify client
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
        require(_value <= allowance[_from][msg.sender]);                          //Allowance verification
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before updating allowance - creates reentrancy opportunity
        if (isContract(_to)) {
            // External call to recipient contract for transfer notification
            _to.call(abi.encodeWithSignature("onTransferReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of call success for compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
    /*
    *   Funtion: Approve usable amount for an account
    *   Type:Public
    *   Parameters:
            @_spender:  address of spender's account
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
            @_spender:  address of other account
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
