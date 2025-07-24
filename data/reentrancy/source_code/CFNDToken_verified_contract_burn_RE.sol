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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls burn() with a contract that has onTokenBurn() fallback. The external call occurs before state changes, allowing the attacker to observe their balance hasn't been reduced yet.
 * 
 * 2. **Transaction 2**: In the onTokenBurn() callback, the attacker can call burn() again or other functions that depend on their current balance. Since balanceOf[msg.sender] hasn't been updated yet, the attacker can bypass balance checks in subsequent calls.
 * 
 * 3. **State Accumulation**: Multiple burn operations can be chained together where each operation sees the previous state before updates, allowing the attacker to burn more tokens than they actually possess by exploiting the timing of state changes.
 * 
 * **Multi-Transaction Nature:**
 * - The vulnerability requires the attacker to deploy a contract with the onTokenBurn() callback first
 * - The exploit spans multiple function calls where the external call in Transaction 1 enables state manipulation in Transaction 2
 * - The persistent state (balanceOf, totalSupply) between transactions is what makes this exploitable
 * - Cannot be exploited in a single atomic transaction due to the required callback mechanism and state persistence
 * 
 * **Why Multiple Transactions Are Required:**
 * - The external call creates a window where old state persists
 * - The callback mechanism requires a separate contract deployment (previous transaction)
 * - State changes accumulate across multiple burn calls, enabling balance manipulation
 * - The exploit depends on the sequence of operations across transaction boundaries
 */
pragma solidity ^0.4.16;

contract CFNDToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function CFNDToken() public {
        totalSupply = 40000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Cryptfunder";
        symbol = "CFND";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify token holder before state changes (vulnerable external call)
        if (msg.sender.call.gas(50000)(bytes4(keccak256("onTokenBurn(uint256)")), _value)) {
            // External call succeeded, continue with burn
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