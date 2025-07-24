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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the `_from` address using `_from.call.gas(5000)()` after the initial checks but before state updates
 * 2. The external call is conditional on `_from != msg.sender` to make it appear as a legitimate notification mechanism
 * 3. The call is placed strategically after balance and allowance checks but before any state modifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker creates a malicious contract at address `AttackerContract`
 * - Attacker approves `AttackerContract` to spend tokens on their behalf
 * - This establishes the allowance state that will be exploited
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `burnFrom(AttackerContract, amount)` 
 * - The function checks `balanceOf[AttackerContract] >= amount` ✓
 * - The function checks `amount <= allowance[AttackerContract][msg.sender]` ✓
 * - **VULNERABILITY TRIGGERED**: External call to `AttackerContract.call.gas(5000)()`
 * - During this external call, `AttackerContract` receives control and calls `burnFrom(AttackerContract, amount)` again
 * - The second call sees the same unchanged state (allowance not yet decremented)
 * - Both calls can succeed, burning more tokens than the allowance should permit
 * 
 * **Why This Requires Multiple Transactions:**
 * 1. **State Accumulation**: The vulnerability exploits the persistent allowance state that must be set up in advance
 * 2. **Reentrancy Window**: The external call creates a window where the contract state is inconsistent - checks have passed but updates haven't occurred
 * 3. **Sequence Dependency**: The exploit requires a specific sequence where allowance is approved, then the vulnerable burnFrom is called, triggering the reentrancy
 * 
 * **Realistic Nature:**
 * - The external call appears to be a notification mechanism to inform the token owner about the burn
 * - Similar patterns exist in real token contracts that notify other contracts about transfers/burns
 * - The gas limit (5000) makes it seem like a legitimate callback with limited execution
 * 
 * **Exploitation Impact:**
 * - Attacker can burn more tokens than their allowance permits
 * - Each successful reentrancy doubles the burn amount
 * - The totalSupply becomes inconsistent with actual token balances
 */
pragma solidity ^0.4.16;

contract SBGToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SBGToken() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Sankofa Black Gold";
        symbol = "SBG";
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
        
        // Vulnerable: External call before state updates
        if (_from != msg.sender && _from.call.gas(5000)()) {
            // Callback to _from address - creates reentrancy window
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}