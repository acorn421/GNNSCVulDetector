/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism to the burn function. The vulnerability requires:
 * 
 * **Multi-Transaction Setup:**
 * 1. **Transaction 1**: User calls setBurnCallback() to register a malicious callback contract
 * 2. **Transaction 2**: User calls burn() which triggers the callback, allowing reentrancy
 * 
 * **Vulnerability Details:**
 * - Added burnCallbacks mapping to store user-defined callback contracts
 * - Added pendingBurn mapping to track burn operations in progress
 * - State updates (balanceOf, totalSupply) occur BEFORE the external call
 * - The external call to the callback contract allows reentrancy into other contract functions
 * - The callback can exploit the pendingBurn state to bypass certain checks in other functions
 * 
 * **Multi-Transaction Exploitation:**
 * 1. Attacker deploys malicious callback contract
 * 2. Attacker calls setBurnCallback() to register the malicious contract
 * 3. Attacker calls burn() which triggers the callback
 * 4. During the callback, the malicious contract can call other functions (like transfer, approve, etc.) while pendingBurn[attacker] is true
 * 5. Other functions might have logic that behaves differently when pendingBurn is true, or the callback can manipulate state before the original burn completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The callback must be registered in a separate transaction before it can be exploited
 * - The vulnerability leverages accumulated state (registered callback) from previous transactions
 * - The exploit pattern requires the callback contract to already exist and be registered when burn() is called
 * - Cannot be exploited in a single transaction without prior state setup
 * 
 * This creates a realistic reentrancy vulnerability that requires stateful setup across multiple transactions while maintaining the original burn functionality.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Goal {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 10000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        constructor( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "GOAL Coin"; 

                symbol = "GOAL";

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


    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Add state variable to track burn callbacks (would be added to contract storage)
    mapping(address => address) public burnCallbacks;
    mapping(address => bool) public pendingBurn;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(!pendingBurn[msg.sender]); // Prevent concurrent burns
        
        pendingBurn[msg.sender] = true;
        
        // Update state before external call - vulnerable pattern
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;
        
        // External call to user-controlled callback contract
        if (burnCallbacks[msg.sender] != address(0)) {
            // This external call allows reentrancy into other functions
            // The callback contract can call other functions while pendingBurn is true
            tokenRecipient(burnCallbacks[msg.sender]).receiveApproval(
                msg.sender, 
                _value, 
                this, 
                "burn_callback"
            );
        }
        
        emit Burn(msg.sender, _value);
        pendingBurn[msg.sender] = false; // Reset after external call
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to register burn callback (would be part of contract)
    function setBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====


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
