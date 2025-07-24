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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder's address before state updates. This creates a vulnerable window where:
 * 
 * 1. **Multi-Transaction Exploitation Pattern**:
 *    - Transaction 1: Attacker calls burnFrom() with a malicious contract as _from address
 *    - The external call triggers the malicious contract's onBurnNotification function
 *    - The malicious contract can then call burnFrom() again with the same allowance/balance before state updates occur
 *    - This allows burning more tokens than the allowance should permit
 * 
 * 2. **State Persistence Between Transactions**:
 *    - The allowance and balanceOf state variables remain unchanged during the external call
 *    - Multiple burnFrom calls can exploit the same allowance amount before it gets decremented
 *    - The vulnerability accumulates across transactions as state changes persist
 * 
 * 3. **Why Multi-Transaction is Required**:
 *    - The vulnerability relies on the external call allowing reentrant access to the same state
 *    - Multiple calls to burnFrom() with the same allowance create the exploit condition
 *    - The attacker needs to set up the malicious contract in one transaction, then exploit in subsequent transactions
 *    - The accumulated effect of multiple burns using the same allowance window creates the vulnerability
 * 
 * 4. **Realistic Integration**:
 *    - The notification call appears as legitimate functionality for token burning events
 *    - The condition (_from != msg.sender) makes it seem like a reasonable notification system
 *    - The vulnerability is subtle and would likely pass initial code review
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability where the exploit requires multiple function calls and depends on persistent state changes between transactions.
 */
pragma solidity ^0.4.16;

contract IBITToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function IBITToken() public {
        totalSupply = 32000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "iBit";
        symbol = "IBIT";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
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

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
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
        
        // External call to burn notification contract before state updates
        if (_from != msg.sender && _from.call(bytes4(keccak256("onBurnNotification(address,uint256)")), msg.sender, _value)) {
            // Call succeeded, continue with burn
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}