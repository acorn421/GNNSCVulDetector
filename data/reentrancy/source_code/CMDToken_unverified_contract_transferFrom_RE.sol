/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before updating the allowance state. The vulnerability violates the Checks-Effects-Interactions (CEI) pattern by placing the external call before the allowance decrement. This enables attackers to exploit the same allowance value multiple times through carefully orchestrated multi-transaction sequences:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker gets approval for X tokens from victim
 * 2. **Transaction 2 (Attack Initiation)**: Attacker calls transferFrom, triggering the onTokenReceived callback
 * 3. **Reentrant Calls**: The callback function initiates additional transferFrom calls before the original allowance is decremented
 * 4. **State Accumulation**: Each reentrant call reads the same (not-yet-decremented) allowance value, enabling multiple transfers
 * 
 * **Why Multi-Transaction is Required:**
 * - The initial approval must be set in a separate transaction
 * - The reentrancy attack requires the callback contract to be deployed and configured
 * - Multiple sequential calls are needed to drain more tokens than the allowance should permit
 * - State persistence between transactions enables the exploitation of the same allowance value
 * 
 * **Realistic Nature:** This vulnerability mirrors real-world patterns where token contracts notify recipient contracts of incoming transfers, making the external call appear legitimate while creating a dangerous reentrancy opportunity.
 */
pragma solidity ^0.4.16;

contract CMDToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function CMDToken() public {
        totalSupply = 200000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "CloudMind";
        symbol = "CMD";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(_value <= allowance[_from][msg.sender]);
        
        // External call before state update - enables reentrancy
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // Call recipient contract's onTokenReceived callback
            (bool callSuccess, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            // Continue execution regardless of callback success
        }
        
        // State update happens AFTER external call - classic CEI violation
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}
