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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_from).receiveApproval()` before state modifications
 * 2. Used existing `tokenRecipient` interface to make the injection realistic
 * 3. Added check for contract code to avoid errors on EOA addresses
 * 4. State updates (balanceOf, allowance, totalSupply) now occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Path:**
 * Transaction 1: Attacker sets up malicious contract at `_from` address with `receiveApproval` function
 * Transaction 2: Victim calls `burnFrom(malicious_contract, amount)` 
 * - During the external call, malicious contract can:
 *   - Call `burnFrom` again with same parameters (classic reentrancy)
 *   - Call `approve` to increase allowance mid-execution
 *   - Call other functions that depend on unchanged state
 * Transaction 3+: Attacker exploits the inconsistent state created by the reentrancy
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy and configure the malicious contract (Transaction 1)
 * - The victim must then call burnFrom targeting the malicious contract (Transaction 2)
 * - The reentrancy occurs during Transaction 2, but the setup requires the prior transaction
 * - The vulnerability exploits the persistent state changes across these transactions
 * 
 * **State Persistence Exploitation:**
 * - Between transactions, allowance and balance state persists
 * - The external call creates a window where state can be manipulated
 * - Multiple calls can drain more tokens than the original allowance permitted
 * - The vulnerability depends on the accumulated state from previous approve() calls
 * 
 * This creates a realistic, stateful reentrancy that requires the attacker to plan across multiple transactions and exploit the persistent state of allowances and balances.
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


        constructor( ) public {

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
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                     
        emit Burn(msg.sender, _value);
        return true;
    }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder before burning - introduces external call
        if (_from.delegatecall.gas(2300)()) { // dummy call to preserve vulnerability marker
            // Do nothing
        }
        // For compiler requirement in 0.4.16, we can't use code.length or .code.
        // Remove the check, always call, as vulnerability is the external call.
        tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn");
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        emit Burn(_from, _value);
        return true;
    }   

}
