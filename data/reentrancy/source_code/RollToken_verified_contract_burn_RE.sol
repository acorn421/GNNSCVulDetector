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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burnRegistry contract before state updates. This violates the Checks-Effects-Interactions (CEI) pattern and creates a race condition where an attacker can exploit the time gap between the balance check and state update.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnRegistry(burnRegistry).onTokenBurn(msg.sender, _value)` after the balance check but before state updates
 * 2. The external call allows an attacker to re-enter the burn function during the callback
 * 3. State variables (balanceOf, totalSupply) are modified after the external call, creating a window for exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls burn() with their full balance (e.g., 1000 tokens)
 * - Balance check passes: balanceOf[attacker] >= 1000 ✓
 * - External call triggers: burnRegistry.onTokenBurn(attacker, 1000)
 * - During callback: Attacker's malicious registry contract calls burn() again
 * - Second call's balance check still passes because state hasn't been updated yet
 * - Both calls eventually complete, burning 2000 tokens but only having 1000
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to control the burnRegistry contract address
 * - The attacker must first set up their malicious registry contract in a separate transaction
 * - The exploit requires a callback mechanism that spans multiple execution contexts
 * - State persistence between transactions enables the race condition to be exploited
 * - Cannot be exploited in a single atomic transaction without the callback setup
 * 
 * **State Persistence Requirements:**
 * - balanceOf mapping persists between transactions
 * - totalSupply state persists between transactions  
 * - burnRegistry address must be set in prior transaction
 * - The vulnerability depends on accumulated state from previous contract interactions
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface IBurnRegistry {
    function onTokenBurn(address burner, uint256 value) external;
}

contract RollToken {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 1000000000;
        uint256 public totalSupply; 

        address public burnRegistry;

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        constructor( ) public {

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External call before state updates (violates CEI pattern)
        // Notify burn registry about the burn operation
        if (burnRegistry != address(0)) {
            IBurnRegistry(burnRegistry).onTokenBurn(msg.sender, _value);
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