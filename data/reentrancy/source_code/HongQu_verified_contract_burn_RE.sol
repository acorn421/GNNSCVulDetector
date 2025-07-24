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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a burn callback mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added state variables for callback registration and pending burn tracking
 * 2. Added external callback call after balance check but before state updates
 * 3. Added functions to register/unregister burn callbacks
 * 4. Stored pending burn amount in state for callback verification
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1**: Attacker registers malicious callback contract
 * - **Transaction 2**: Attacker calls burn(), triggering callback which can observe pendingBurnAmount
 * - **Transaction 3**: Callback contract calls burn() again while original burn is still pending
 * - **Multiple subsequent transactions**: Chain additional burns using the same pattern
 * 
 * **Why Multi-Transaction:**
 * - Callback registration must happen in a separate transaction before exploitation
 * - Each burn call creates a window where pendingBurnAmount shows uncommitted burn
 * - The vulnerability depends on accumulated state from callback registration
 * - Exploitation requires sequence: register → burn → callback → re-burn
 * 
 * The vulnerability violates checks-effects-interactions by placing the external call between balance verification and state updates, creating a multi-transaction reentrancy window.
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


    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) public burnCallbackRegistered;
    mapping (address => address) public burnCallbackContract;
    mapping (address => uint256) public pendingBurnAmount;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        
        // Store pending burn amount for callback verification
        pendingBurnAmount[msg.sender] = _value;
        
        // Call external callback if registered (vulnerable placement)
        if (burnCallbackRegistered[msg.sender]) {
            tokenRecipient callback = tokenRecipient(burnCallbackContract[msg.sender]);
            callback.receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // State updates after external call (vulnerable)
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;
        
        // Clear pending burn amount
        pendingBurnAmount[msg.sender] = 0;
        
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function registerBurnCallback(address _callback) public {
        burnCallbackRegistered[msg.sender] = true;
        burnCallbackContract[msg.sender] = _callback;
    }
    
    function unregisterBurnCallback() public {
        burnCallbackRegistered[msg.sender] = false;
        burnCallbackContract[msg.sender] = address(0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====


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