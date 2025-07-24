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
 * This vulnerability injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Specific Changes Made:**
 *    - Added an external call to `IBurnNotifier(burnNotifier).onBurn(msg.sender, _value)` before state updates
 *    - The external call occurs after the balance check but before the actual balance and totalSupply modifications
 *    - This violates the Checks-Effects-Interactions pattern by placing an external call before state changes
 * 
 * 2. **Multi-Transaction Exploitation Mechanism:**
 *    - **Transaction 1**: Attacker calls burn() with legitimate balance, external call triggers attacker's malicious contract
 *    - **Transaction 2**: During the callback, attacker's contract calls burn() again before the first transaction's state updates are applied
 *    - **Transaction 3+**: This can be repeated multiple times, allowing the attacker to burn more tokens than they actually possess
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability exploits the timing window between the external call and state updates
 *    - Each reentrancy call creates a new transaction context where the balance check passes because previous burns haven't been applied yet
 *    - The attacker must accumulate multiple pending burn operations across several transaction calls
 *    - Single transaction exploitation is impossible because the external call must return control to complete the state updates
 *    - The exploit requires the attacker to set up their malicious contract beforehand (separate transaction) and then orchestrate the sequence of burn calls
 * 
 * 4. **Stateful Nature:**
 *    - The vulnerability depends on the persistent state of balanceOf[msg.sender] between transactions
 *    - Each call passes the balance check because the state hasn't been updated from previous calls
 *    - The accumulated effect across multiple transactions allows burning more tokens than owned
 * 
 * **Prerequisites for Exploitation:**
 * - The contract must have a burnNotifier address set (requires prior transaction)
 * - Attacker must deploy a malicious contract implementing IBurnNotifier (separate transaction)
 * - Attacker must have some initial token balance to pass the first check
 * 
 * This creates a realistic multi-transaction reentrancy scenario where the attacker can drain more tokens than they legitimately possess by exploiting the delayed state updates across multiple function calls.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Define the external interface for burn notification
interface IBurnNotifier {
    function onBurn(address _from, uint256 _value) external;
}

/*
*ERC20
*
*/
contract ASSET {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        
        uint256 public totalSupply; 
        uint256 public total = 1000000000;

        // <-- Added missing variable declaration -->
        address public burnNotifier;
        
        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function ASSET( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "ASSET"; 

                symbol = "ASSET";

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
        
        // Notify external contract about burn event (vulnerability injection)
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onBurn(msg.sender, _value);
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