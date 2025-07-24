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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burn callback handler before state updates. This creates a classic checks-effects-interactions pattern violation.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnCallback(burnCallbackHandler).onBurn(msg.sender, _value)` before state modifications
 * 2. The callback occurs after the balance check but before the balance and totalSupply updates
 * 3. The `burnCallbackHandler` would be a state variable that can be set by users or contract admin
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be effectively exploited:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker sets their malicious contract as the `burnCallbackHandler`
 * - Attacker deposits tokens to have sufficient balance
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burn()` with some amount
 * - During the `onBurn` callback, the attacker's contract can call `burn()` again
 * - Since state hasn't been updated yet, the balance check passes
 * - This allows burning more tokens than the attacker actually has
 * 
 * **Transaction 3+ (Repeated Exploitation):**
 * - Attacker can repeat the process across multiple transactions
 * - Each transaction builds on the state modifications from previous transactions
 * - The accumulated effect allows draining more tokens than legitimately owned
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability relies on the persistent state of `balanceOf` and `totalSupply` that accumulates across transactions
 * 2. **Sequential Exploitation**: Each transaction modifies the contract state, enabling more effective exploitation in subsequent transactions
 * 3. **Gas Limitations**: Complex reentrancy attacks often require multiple transactions due to gas limits
 * 4. **State Accumulation**: The attacker needs to build up a position across multiple transactions to maximize the exploit
 * 
 * **Exploitation Dependencies:**
 * - Requires setting up the callback handler (Transaction 1)
 * - Requires initial balance setup (potentially multiple transactions)
 * - Requires sequential burn operations to accumulate the exploit effect
 * - Each transaction depends on the state changes from previous transactions
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world reentrancy attacks seen in DeFi protocols where external callbacks are used for notifications and integrations.
 */
pragma solidity ^0.4.16;

contract CMDToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Added burnCallbackHandler declaration
    address public burnCallbackHandler;

    // Moved IBurnCallback interface outside the contract
}

// Added the IBurnCallback interface outside the contract as required in Solidity 0.4.x
interface IBurnCallback {
    function onBurn(address burner, uint256 value) external;
}

contract CMDTokenNew is CMDToken {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // Constructor syntax updated
    function CMDTokenNew() public {
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
        // Notify external burn callback handler before state updates
        if (burnCallbackHandler != address(0)) {
            IBurnCallback(burnCallbackHandler).onBurn(msg.sender, _value);
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
