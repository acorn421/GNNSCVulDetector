/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller's contract before state updates. This creates a classic violation of the Checks-Effects-Interactions pattern. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **Transaction 1**: Attacker calls burn() which triggers the external call back to their contract. During this callback, the attacker can call burn() again since balanceOf hasn't been updated yet. However, the second call will also trigger the callback, creating a chain that must be carefully managed across transaction boundaries.
 * 
 * 2. **Transaction 2+**: The attacker can exploit the fact that the external call happens before state updates by implementing a contract that tracks burn attempts and manipulates the sequence across multiple transactions. The attacker can use a stateful approach where they partially burn tokens in one transaction, then exploit the callback mechanism in subsequent transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker calls burn(100) → External call triggered → Attacker's contract receives callback and stores state about the burn
 * - Transaction 2: Attacker calls burn(50) → External call triggered → Attacker's contract can now exploit the accumulated state knowledge to manipulate the burn sequence
 * - The vulnerability becomes exploitable because the attacker can maintain state between transactions and use the callback mechanism to burn more tokens than they should have access to
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction reentrancy would cause immediate recursion, but the attacker needs to carefully orchestrate the callbacks across multiple transactions to avoid gas limits and stack overflow
 * - The stateful nature allows the attacker to accumulate information about burn attempts and exploit timing between external calls and state updates
 * - Each transaction can perform partial exploitation while maintaining state for the next transaction's exploitation phase
 * 
 * The vulnerability is realistic because developers often add notification mechanisms for important operations like token burns, and the external call placement before state updates is a common mistake in real-world contracts.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ONID {

    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    event Transfer(address indexed from, address indexed to, uint256 value);


    event Burn(address indexed from, uint256 value);
    uint256 initialSupply=10000000000000;
        string tokenName = "ONID";
        string tokenSymbol = "ONID";

    constructor(
        
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;               
        name = tokenName;                                  
        symbol = tokenSymbol;                               
    }


    function _transfer(address _from, address _to, uint _value) internal {

        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }


    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external contract about burn (vulnerable to reentrancy)
        if (msg.sender != address(this)) {
            (bool callSuccess, ) = msg.sender.call(abi.encodeWithSignature("onBurnNotification(uint256)", _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;          
        totalSupply -= _value;                      
        emit Burn(msg.sender, _value);
        return true;
    }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}