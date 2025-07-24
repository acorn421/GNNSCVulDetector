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
 * **Specific Changes Made:**
 * 
 * 1. **Added State Tracking**: Introduced `pendingBurns` mapping to track accumulated burn amounts across transactions
 * 2. **External Call Injection**: Added call to `IBurnNotification(burnNotificationContract).onBurnInitiated()` after balance check but before state updates
 * 3. **State Update Reordering**: Moved balance and totalSupply updates to occur AFTER the external call, violating Checks-Effects-Interactions pattern
 * 4. **Multi-Transaction Enabler**: The `pendingBurns` state persists between transactions and is passed to external contracts
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker has 100 tokens
 * - Calls `burn(50)` 
 * - `pendingBurns[attacker] = 50`
 * - External call to `onBurnInitiated(attacker, 50, 50)` 
 * - During callback, attacker can see pendingBurns state and plan next attack
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `burn(100)`
 * - Balance check passes: `balanceOf[attacker] = 100 >= 100` ✓
 * - `pendingBurns[attacker] = 150` (accumulated from previous call)
 * - External call with `onBurnInitiated(attacker, 100, 150)`
 * - **Reentrancy occurs here:** Attacker's malicious contract calls `burn(100)` again
 * 
 * **Transaction 3 (Reentrancy Exploitation):**
 * - Second `burn(100)` call during callback
 * - Balance check still passes: `balanceOf[attacker] = 100 >= 100` ✓ (state not yet updated)
 * - `pendingBurns[attacker] = 250` 
 * - Another external call triggers, potentially enabling more reentrancy
 * - Eventually state updates execute, but attacker has burned 300 tokens with only 100 balance
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The `pendingBurns` mapping accumulates values across multiple calls, creating a growing attack surface
 * 2. **Timing Dependencies**: The vulnerability relies on the specific timing of external calls relative to state updates across multiple transactions
 * 3. **Persistent State Exploitation**: Each transaction leaves the contract in a state that enables the next phase of the attack
 * 4. **Callback Coordination**: The attacker's malicious contract needs multiple interactions to coordinate the complex reentrancy sequence
 * 
 * **Realistic Nature:**
 * - Burn notifications are common in DeFi protocols for integration with other contracts
 * - The `pendingBurns` tracking appears as a legitimate feature for monitoring burn activity
 * - The external call placement seems reasonable for notifying other systems before finalizing the burn
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Definition of the burn notification interface
interface IBurnNotification {
    function onBurnInitiated(address from, uint256 value, uint256 totalPending) external;
}

contract SwarmBzzTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;
    
    // Track pending burns to enable multi-transaction exploitation
    mapping(address => uint256) public pendingBurns;
    
    // Address for the burn notification contract
    address public burnNotificationContract;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    
    // Updated constructor definition (for Solidity >=0.4.22 use constructor, for 0.4.16 ok as-is but warning remains)
    function SwarmBzzTokenERC20(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function setBurnNotificationContract(address _contract) public {
        burnNotificationContract = _contract;
    }
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add to pending burns for multi-transaction tracking
        pendingBurns[msg.sender] += _value;
        // External call to notify burn listeners before state updates
        // This creates a reentrancy window where attacker can call burn again
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurnInitiated(msg.sender, _value, pendingBurns[msg.sender]);
        }
        // State changes happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        pendingBurns[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
