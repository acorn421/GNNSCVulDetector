/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **Specific Changes Made:**
 * 
 * 1. **Reordered Operations**: Moved the `_transfer(_from, _to, _value)` call before the allowance decrement
 * 2. **Added Callback Mechanism**: Introduced a callback to the recipient contract using the existing `tokenRecipient` interface
 * 3. **Critical State Window**: Created a window where tokens are transferred but allowance is not yet decremented
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - User approves allowance for malicious contract: `approve(maliciousContract, 1000)`
 * - State: `allowance[user][maliciousContract] = 1000`
 * 
 * **Transaction 2 (Initial Call):**
 * - Malicious contract calls `transferFrom(user, maliciousContract, 500)`
 * - Flow: Check allowance (✓ 500 ≤ 1000) → Transfer tokens → **Callback triggered**
 * - During callback: allowance is still 1000 (not decremented yet)
 * 
 * **Transaction 3 (Reentrancy Attack):**
 * - Inside the callback, malicious contract calls `transferFrom(user, maliciousContract, 500)` again
 * - Flow: Check allowance (✓ 500 ≤ 1000) → Transfer tokens → Callback → Decrement allowance
 * - State after callback: `allowance[user][maliciousContract] = 500`
 * 
 * **Transaction 4 (Completion):**
 * - Original call completes, decrements allowance: `allowance[user][maliciousContract] = 0`
 * - **Result**: Malicious contract extracted 1000 tokens using only 500 allowance
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The allowance state must persist between the callback and the allowance decrement
 * 2. **Callback Execution**: The callback creates a separate execution context that can initiate new transactions
 * 3. **Accumulated State**: The vulnerability depends on the accumulated allowance state from previous approve() calls
 * 4. **Sequence Dependency**: The attack requires a specific sequence: approve → transferFrom → callback → recursive transferFrom
 * 
 * **Technical Details:**
 * - The vulnerability exploits the time window between token transfer and allowance decrement
 * - Uses the existing `tokenRecipient` interface for realistic callback implementation
 * - Maintains backward compatibility with non-contract recipients
 * - The `try/catch` pattern makes the code appear production-ready
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
contract HongQu {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 5000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function HongQu( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "HongQu"; 

                symbol = "HQC";

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
        _transfer(_from, _to, _value);
        
        // Enhanced token transfer with callback notification
        if (_to != address(0) && isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        return true;
    }

    function isContract(address _addr) private view returns (bool) {
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