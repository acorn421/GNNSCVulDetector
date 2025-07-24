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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a window where:
 * 
 * 1. **Stateful Nature**: The vulnerability depends on the persistent allowance state that remains unchanged during the external call
 * 2. **Multi-Transaction Exploitation**: Requires multiple coordinated transactions:
 *    - Transaction 1: Initial transferFrom call triggers external call, during which attacker can reenter
 *    - Transaction 2+: Recursive calls exploit unchanged allowance before it gets decremented
 *    - Each reentrancy call can transfer the same allowance amount repeatedly
 * 
 * **Exploitation Scenario:**
 * - Attacker gets approved for X tokens
 * - Attacker deploys malicious contract as recipient
 * - When transferFrom is called, the external call triggers the malicious contract's onTokenReceived
 * - The malicious contract calls transferFrom again with the same allowance (still unchanged)
 * - This can be repeated multiple times before the original allowance is decremented
 * - Each recursive call transfers the full allowance amount, allowing theft of X * N tokens
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires state accumulation across multiple function calls
 * - Each reentrancy call is a separate execution context that depends on the persistent allowance state
 * - The exploit cannot be done atomically in a single transaction - it requires the external call to trigger subsequent transactions
 * - The attacker needs to coordinate multiple transferFrom calls that depend on the same unchanged allowance state
 */
pragma solidity ^0.4.16;

contract SealToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SealToken() public {
        totalSupply = 1200000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Seal";
        symbol = "Seal";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Added external call before state update - creates reentrancy window
        uint32 size;
        assembly {
            size := extcodesize(_to)
        }
        if(size > 0) {
            bool notificationSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value);
            require(notificationSuccess);
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
