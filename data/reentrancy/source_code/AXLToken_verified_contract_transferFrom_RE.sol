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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * 1. **Transaction 1 Setup**: Attacker sets up allowance and deploys malicious contract
 * 2. **Transaction 2 Initial Attack**: Calls transferFrom, which triggers the external call to the malicious contract's onTokenReceived function
 * 3. **Reentrancy Exploitation**: The malicious contract can reenter transferFrom multiple times before the allowance is decremented, draining more tokens than allowed
 * 4. **State Persistence**: The allowance state persists between transactions, enabling the accumulation of unauthorized transfers
 * 
 * The vulnerability requires multiple transactions because:
 * - The attacker needs to first approve allowance (separate transaction)
 * - The malicious contract must be deployed and configured (separate transaction)
 * - The actual exploitation involves the external call triggering reentrancy back to transferFrom
 * - Each reentrant call can transfer the full allowance amount since the allowance hasn't been decremented yet
 * 
 * This creates a realistic multi-transaction reentrancy where the attacker can drain significantly more tokens than their allowance permits by exploiting the state persistence across the reentrant calls.
 */
pragma solidity ^0.4.16;

contract AXLToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function AXLToken() public {
        totalSupply = 150000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Axle Project";
        symbol = "AXL";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates - potential reentrancy point
        // In Solidity 0.4.16, use extcodesize for contract detection
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // low-level call with no return data check (except for success)
            if (!_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                revert();
            }
        }
        
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
