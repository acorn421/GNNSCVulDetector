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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a reward contract after the balance check but before state updates. This creates a reentrancy window where an attacker can:
 * 
 * 1. **Transaction 1**: Call burn() with a legitimate amount, triggering the external call to onBurn()
 * 2. **During external call**: The attacker's malicious reward contract re-enters burn() with the same or different amount
 * 3. **Exploitation**: Since balanceOf hasn't been updated yet, the require check passes again, allowing multiple burns with the same balance
 * 
 * **Multi-Transaction Nature:**
 * - The vulnerability requires setting up a malicious reward contract in a previous transaction
 * - The attack unfolds across multiple nested calls within the same transaction tree
 * - Each re-entrant call sees the same unchanged balance state, enabling over-burning
 * - The attacker can burn more tokens than they actually possess by exploiting the state inconsistency
 * 
 * **Stateful Dependency:**
 * - Requires the rewardContract address to be set (persistent state)
 * - The attacker's balance state persists between re-entrant calls
 * - The vulnerability exploits the temporary inconsistent state where checks pass but updates haven't occurred
 * 
 * **Realistic Integration:**
 * - Reward systems for token burns are common in DeFi protocols
 * - The external call placement appears natural for notification purposes
 * - The vulnerability is subtle and could easily be missed in code review
 */
/**
 *Submitted for verification at Etherscan.io on 2018-07-29
*/

pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Interface for reward contract
interface IRewardContract {
    function onBurn(address _from, uint256 _value) external;
}

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

        // Added rewardContract state variable
        address public rewardContract;

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        constructor( ) public {

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
        
        // External call to reward contract before state update - creates reentrancy window
        if (rewardContract != address(0)) {
            IRewardContract(rewardContract).onBurn(msg.sender, _value);
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
