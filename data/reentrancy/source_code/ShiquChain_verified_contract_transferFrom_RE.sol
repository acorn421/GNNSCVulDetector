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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification call before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **CHANGES MADE:**
 * 1. Added an external call to `tokenRecipient(_to).receiveApproval()` before decrementing the allowance
 * 2. This creates a CEI (Checks-Effects-Interactions) pattern violation
 * 3. The allowance state is checked but not updated until after the external call
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * Transaction 1: Attacker sets up initial allowance and deploys malicious contract
 * Transaction 2: Attacker calls transferFrom() with malicious contract as recipient
 * Transaction 3: During receiveApproval callback, attacker re-enters transferFrom() before allowance is decremented
 * Transaction 4: Attacker can drain tokens beyond intended allowance across multiple reentrant calls
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * - The allowance state persists between transactions
 * - Each transaction can check the same allowance value before it's decremented
 * - The vulnerability accumulates across multiple calls as the allowance isn't properly decremented until after external calls
 * - A single transaction alone wouldn't provide sufficient time/state for complex exploitation - the multi-transaction nature allows the attacker to build up state and execute the attack progressively
 * 
 * **STATEFUL NATURE:**
 * - The allowance mapping state persists between transactions
 * - Each reentrancy call can read the stale allowance value
 * - The vulnerability depends on the accumulated effect of multiple state reads before any state updates occur
 * - The attacker can craft a sequence of transactions that progressively exploit the timing window
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
contract ShiquChain {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 10000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function ShiquChain( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "ShiquChain"; 

                symbol = "SQC";

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(_value <= allowance[_from][msg.sender]);
        
        // Notify recipient before updating allowance (vulnerable to reentrancy)
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
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
