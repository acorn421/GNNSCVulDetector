/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * **Vulnerability Details:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call `_from.call()` after the require checks but before state updates
 * - The call attempts to notify the token holder about the burn operation
 * - This violates the Checks-Effects-Interactions (CEI) pattern by placing an external call before state modifications
 * - The external call only occurs when `_from != msg.sender`, making it appear as a legitimate notification feature
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract and gets token allowance
 * - Attacker's contract implements a fallback function that calls `burnFrom` again
 * - Initial state: `allowance[victim][attacker] = 1000`, `balanceOf[victim] = 1000`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `burnFrom(victim, 600)` 
 * - Function checks pass: `balanceOf[victim] >= 600` ✓, `allowance <= 600` ✓
 * - External call triggers victim's fallback function
 * - **Before state updates occur**, the fallback function calls `burnFrom(victim, 400)`
 * - Second call also passes checks (state hasn't been updated yet)
 * - This creates a recursive burn scenario where more tokens are burned than should be possible
 * 
 * **Transaction 3 (State Corruption):**
 * - When the call stack unwinds, state updates occur multiple times
 * - Final result: More tokens burned than the original allowance permitted
 * - `totalSupply` is reduced more than it should be
 * - Victim's balance is reduced beyond what was authorized
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **Stateful Dependency:**
 * - The vulnerability requires prior state setup (allowance approval) in Transaction 1
 * - The exploitation depends on the accumulated state from previous transactions
 * - Each recursive call depends on the state not yet being updated from previous calls
 * 
 * **Multi-Call Exploitation:**
 * - Cannot be exploited in a single atomic transaction without the external call mechanism
 * - Requires the external call to trigger reentrancy during the burn process
 * - The recursive nature means multiple function invocations are necessary for exploitation
 * - The vulnerability accumulates damage across multiple nested calls within the transaction sequence
 * 
 * **State Persistence:**
 * - The vulnerability exploits the gap between state checks and state updates
 * - Each nested call sees the same pre-update state, allowing unauthorized burns
 * - The damage persists across the entire call sequence and affects permanent contract state
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world patterns where notification mechanisms or callback systems introduce security flaws through improper state management.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-28
*/

/**
 *Submitted for verification at Etherscan.io on 2018-07-29
*/

pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function Alipay( ) public {

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
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                     
        Burn(msg.sender, _value);
        return true;
    }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder about the burn through external call
        // This violates checks-effects-interactions pattern
        if (_from != msg.sender) {
            // External call before state updates - creates reentrancy opportunity
            bool notified = _from.call(bytes4(keccak256("burnNotification(address,uint256)")), msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        Burn(_from, _value);
        return true;
    }   

}