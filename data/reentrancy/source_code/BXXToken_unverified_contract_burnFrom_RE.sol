/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the _from address before state updates. This creates a classic CEI (Checks-Effects-Interactions) pattern violation that enables multi-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_from.call()` with callback signature `onBurnFrom(address,uint256)`
 * 2. Positioned the external call AFTER the initial checks but BEFORE state modifications
 * 3. Added a check for contract code existence to make the callback realistic
 * 4. Added a require statement for callback success to maintain function robustness
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burnFrom(victimContract, amount)` where `victimContract` is a malicious contract
 * 2. **During Transaction 1**: The external callback `onBurnFrom` is triggered in the victim contract
 * 3. **Reentrancy Window**: Inside the callback, the victim contract can call `approve(attacker, newAmount)` to increase allowance
 * 4. **Continued Reentrancy**: The victim contract then calls `burnFrom(victimContract, additionalAmount)` again
 * 5. **State Manipulation**: The reentrant call succeeds because the allowance was increased in step 3, but the original allowance hasn't been decremented yet
 * 6. **Result**: More tokens are burned than the original allowance should have permitted
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first set up the victim contract with the malicious callback logic
 * - The victim contract must have sufficient token balance and grant initial allowance (separate transactions)
 * - The exploitation happens through the callback mechanism which creates a call stack that spans multiple logical transaction boundaries
 * - The state persistence (allowance and balance) between the setup and exploitation phases is crucial for the attack to work
 * 
 * **State Persistence Elements:**
 * - `allowance[_from][msg.sender]` - can be manipulated during reentrancy
 * - `balanceOf[_from]` - checked before the external call, can be exploited multiple times
 * - `totalSupply` - can be decremented more than intended through multiple reentrant burns
 * 
 * This vulnerability is realistic because notification callbacks are common in advanced token contracts, and the CEI pattern violation is a subtle but dangerous mistake that has appeared in real-world contracts.
 */
pragma solidity ^0.4.16;

contract BXXToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function BXXToken() public {
        totalSupply = 1250000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "BAANX.COM LTD";
        symbol = "BXX";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
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

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
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
        
        // INJECTED: External callback to notify _from about burn operation
        // This creates a reentrancy opportunity before state updates
        if (isContract(_from)) {
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onBurnFrom(address,uint256)", msg.sender, _value));
            require(callSuccess, "Callback failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }

    // Helper function to check if an address is a contract (for Solidity <0.5.0)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
