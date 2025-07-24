/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. This creates a classic reentrancy pattern where:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract and gets tokens/allowance set up
 * 2. **Attack Transaction 1**: Attacker calls burnFrom() → triggers external call to malicious contract → malicious contract re-enters burnFrom() while original state is unchanged
 * 3. **Attack Transaction 2+**: Subsequent re-entrant calls exploit the fact that balanceOf, allowance, and totalSupply haven't been updated yet
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first set up a malicious contract with the onTokenBurn function
 * - The exploit depends on the state persistence between the initial call and re-entrant calls
 * - Multiple burnFrom calls are needed to drain more tokens than the original allowance permitted
 * - The attack relies on the accumulated effect of multiple state-inconsistent burns
 * 
 * **Realistic Justification:**
 * The external call is disguised as a "token burn notification" feature, which is a common pattern in modern tokens for integration with DeFi protocols. This makes the vulnerability subtle and realistic, as developers might add such functionality for legitimate purposes without realizing the security implications of calling external contracts before state updates.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Goal {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 10000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function Goal( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "GOAL Coin"; 

                symbol = "GOAL";

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
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                     
        Burn(msg.sender, _value);
        return true;
    }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder about the burn - VULNERABLE: External call before state updates
        if (_from != msg.sender) {
            // Call to potentially malicious contract before state changes
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result for "backward compatibility"
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        Burn(_from, _value);
        return true;
    }   

}