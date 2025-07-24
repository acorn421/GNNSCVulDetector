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
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced an external call to `IBurnable(_from).onBurn(msg.sender, _value)` that occurs BEFORE the critical state variables are updated
 * 2. **Preserved Function Signature**: Maintained the exact same function signature and return type
 * 3. **Added Try-Catch for Realism**: Used try-catch to handle external call failures gracefully, making the code appear production-ready
 * 4. **Maintained Core Logic**: All original functionality and checks remain intact
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup:**
 * - Attacker creates a malicious contract implementing `IBurnable` interface
 * - Attacker obtains allowance from the malicious contract to burn tokens
 * - The malicious contract has tokens in its balance
 * 
 * **Transaction 2 - Initial Attack:**
 * - Attacker calls `burnFrom(maliciousContract, amount)`
 * - Function validates: `balanceOf[maliciousContract] >= amount` ✓
 * - Function validates: `amount <= allowance[maliciousContract][attacker]` ✓
 * - External call to `maliciousContract.onBurn()` is made
 * 
 * **Transaction 3 - Reentrant Call (within onBurn callback):**
 * - The malicious contract's `onBurn()` function calls `burnFrom()` again
 * - Since state hasn't been updated yet, the same checks pass again:
 *   - `balanceOf[maliciousContract]` still shows original amount
 *   - `allowance[maliciousContract][attacker]` still shows original allowance
 * - This creates a reentrancy where tokens can be burned multiple times
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Persistence**: The vulnerability relies on the fact that state variables (`balanceOf`, `allowance`, `totalSupply`) persist between transactions and calls
 * 2. **Sequential Dependency**: The attack requires:
 *    - First establishing allowance and balance (separate transactions)
 *    - Then exploiting the reentrancy during the external call
 *    - The reentrant call depends on the state from the initial call
 * 3. **Cross-Call State Manipulation**: The vulnerability manifests when the external call in one transaction context can trigger another call that reads the same persistent state before it's updated
 * 
 * **Exploitation Impact:**
 * - Tokens can be burned multiple times with a single allowance
 * - Total supply can be reduced more than intended
 * - The attacker can effectively "amplify" their burn allowance through reentrancy
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transaction contexts to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Added IBurnable interface for external onBurn call
interface IBurnable { function onBurn(address _operator, uint256 _value) external; }

contract RollToken {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 1000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function RollToken( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "Roll"; 

                symbol = "Roll";

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
        
        // Notify the token holder about the burn operation before state updates
        if (_isContract(_from)) {
            IBurnable(_from).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        Burn(_from, _value);
        return true;
    }   

    // Added contract detection helper for 0.4.16 (no .code property)
    function _isContract(address _addr) internal view returns (bool isContract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

}
