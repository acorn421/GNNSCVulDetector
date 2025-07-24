/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (_from) before updating the allowance state. The vulnerability creates a window where balanceOf and totalSupply have been updated but allowance has not yet been decremented, allowing for multi-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. **External Call Addition**: Added a callback to `tokenRecipient(_from).receiveApproval()` when `_from` is a contract
 * 2. **State Update Reordering**: Moved the `allowance[_from][msg.sender] -= _value` line to occur AFTER the external call
 * 3. **Inconsistent State Window**: Created a period where `balanceOf` and `totalSupply` are updated but `allowance` is not yet decremented
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls `burnFrom()` with a malicious contract as `_from`
 * - `balanceOf[_from]` is decremented
 * - `totalSupply` is decremented  
 * - External call triggers attacker's `receiveApproval()` function
 * - During reentrancy: `allowance[_from][msg.sender]` is still at original value
 * - Attacker can call `burnFrom()` again with same allowance
 * 
 * Transaction 2: In the reentrant call, the attacker exploits the inconsistent state
 * - `allowance` check passes (not yet decremented from Transaction 1)
 * - `balanceOf` check may fail if insufficient balance, but attacker could have prepared multiple accounts
 * - This enables burning more tokens than originally approved
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger reentrancy during the inconsistent state window
 * - The attacker needs to set up a malicious contract as `_from` in advance (separate transaction)
 * - The exploitation relies on the persistent state inconsistency between balance/supply updates and allowance updates
 * - Single transaction exploitation is limited by gas constraints and the need for complex contract interactions
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                     
        Burn(msg.sender, _value);
        return true;
    }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                       
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;                            
        
        // Notify burn callback contract if _from is a contract
        if (isContract(_from)) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;            
        Burn(_from, _value);
        return true;
    }  
    
    // Helper for contract detection for <0.5.0
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

}
