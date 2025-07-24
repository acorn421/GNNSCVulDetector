/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Modified the burn function to introduce a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Introduced an external call to `IBurnNotification(burnNotifier).onBurn(msg.sender, _value)` after the balance check but before the state updates (violating Checks-Effects-Interactions pattern).
 * 
 * 2. **State Variables Required**: This assumes the contract has a `burnNotifier` state variable and `IBurnNotification` interface defined elsewhere in the contract.
 * 
 * 3. **Multi-Transaction Exploitation Scenario**:
 *    - **Transaction 1**: User calls burn(100) with balance of 100 tokens
 *    - **During External Call**: Malicious burnNotifier contract receives onBurn callback
 *    - **Reentrant Call**: Malicious contract calls burn(100) again before first transaction completes
 *    - **Transaction 2**: Second burn call passes the require check (balance still 100) and makes another external call
 *    - **Continued Reentrancy**: This can continue until gas runs out, allowing attacker to burn more tokens than their actual balance
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the attacker to have control over the `burnNotifier` contract
 *    - The attacker must set up the malicious contract as the burn notifier in a previous transaction
 *    - Each reentrant call represents a separate logical transaction in the attack sequence
 *    - The exploit accumulates across multiple nested calls, each checking the same unchanged balance
 * 
 * 5. **Stateful Nature**:
 *    - The `balanceOf` and `totalSupply` state variables persist between calls
 *    - The vulnerability depends on these state variables not being updated until after the external call
 *    - The attacker's malicious contract must be registered as the burn notifier in persistent contract state
 * 
 * This creates a realistic reentrancy vulnerability where the external call allows multiple burns to occur before the balance is properly decremented, enabling the attacker to burn more tokens than they actually own.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface IBurnNotification {
    function onBurn(address from, uint256 value) external;
}

/*
*ERC20
*
*/
contract Alipay {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 1000000000;
        uint256 public totalSupply; 

        address public burnNotifier; // Added declaration for burnNotifier

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        constructor() public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "Alipay"; 

                symbol = "AP";

        }

     function _transfer(address _from, address _to, uint _value) internal {
    
        require(_to != 0x0);
     
        require(balanceOf[_from] >= _value);
     
        require(balanceOf[_to] + _value >= balanceOf[_to]);
  
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
   
        balanceOf[_from] -= _value;
    
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
  
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
        
        // External call to notify burn recipient before state updates
        // This creates reentrancy opportunity where attacker can call burn again
        if (burnNotifier != address(0)) {
            IBurnNotification(burnNotifier).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                     
        Burn(msg.sender, _value);
        return true;
    }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        Burn(_from, _value);
        return true;
    }   

}
