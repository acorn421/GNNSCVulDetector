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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic reentrancy attack vector where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_to).receiveApproval()` after the allowance check but before the allowance update
 * 2. Used try-catch to maintain backward compatibility with non-contract recipients
 * 3. Moved the allowance decrease to occur AFTER the external call, violating the checks-effects-interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker gets approved allowance of 100 tokens from victim
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls transferFrom(victim, maliciousContract, 50) 
 *    - Function checks allowance (50 <= 100) ✓
 *    - External call to maliciousContract.receiveApproval() triggers reentrancy
 *    - **Reentrant Call**: maliciousContract calls transferFrom(victim, attacker, 50) again
 *    - Nested call checks allowance (50 <= 100) ✓ (allowance not yet decreased!)
 *    - Nested call completes, transferring 50 tokens to attacker
 *    - Original call resumes, decreases allowance by 50, transfers another 50 tokens
 *    - **Result**: 100 tokens transferred using only 50 allowance
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the initial approval transaction to set up the allowance state
 * - The exploitation requires the external call to trigger reentrancy during the transfer
 * - The attacker's contract needs to be deployed and ready to receive the callback
 * - Multiple state reads of the same allowance value enable the double-spend
 * 
 * **State Persistence Critical to Exploitation:**
 * - `allowance` mapping persists between the original and reentrant calls
 * - During reentrancy, the allowance hasn't been decreased yet, allowing multiple transfers
 * - The vulnerability exploits the time gap between allowance check and allowance update
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world ERC20 token vulnerabilities seen in production contracts.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming transfer (introduces external call)
        if (_isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
            // Success - continue with transfer
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper to replicate the _to.code.length > 0 check in 0.4.16
    function _isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        Burn(_from, _value);
        return true;
    }   

}
