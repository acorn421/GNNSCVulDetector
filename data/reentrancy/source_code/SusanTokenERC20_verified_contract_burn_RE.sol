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
 * 1. **Added State Variables**: 
 *    - `burnNotificationContract` mapping to store user-controlled notification contracts
 *    - `pendingBurnAmount` mapping to track pending burn amounts between transactions
 * 
 * 2. **Added External Call Before State Updates**:
 *    - Introduced call to `BurnNotificationInterface(burnNotificationContract[msg.sender]).onBurnNotification(msg.sender, _value)` after the balance check but before state modifications
 *    - This violates the Checks-Effects-Interactions pattern
 * 
 * 3. **Added Helper Function**:
 *    - `setBurnNotificationContract()` allows users to set their notification contract address
 * 
 * 4. **Modified State Update Logic**:
 *    - Uses `pendingBurnAmount[msg.sender]` instead of `_value` for state updates
 *    - Clears pending amount after processing
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Step 1 - Setup (Transaction 1):**
 * - Attacker deploys malicious contract implementing `BurnNotificationInterface`
 * - Attacker calls `setBurnNotificationContract(maliciousContract)`
 * - Attacker acquires some tokens (e.g., 100 tokens)
 * 
 * **Step 2 - Exploitation (Transaction 2):**
 * - Attacker calls `burn(50)` 
 * - Function checks `balanceOf[attacker] >= 50` ✓ (100 >= 50)
 * - Sets `pendingBurnAmount[attacker] = 50`
 * - Calls malicious contract's `onBurnNotification()`
 * - **Malicious contract re-enters `burn(50)` again**
 * - Re-entrant call checks `balanceOf[attacker] >= 50` ✓ (still 100, state not updated yet)
 * - Sets `pendingBurnAmount[attacker] = 50` (overwrites previous)
 * - External call happens again (could trigger more re-entries)
 * - Eventually state updates: `balanceOf[attacker] -= 50` (burns only 50 tokens)
 * - But attacker effectively triggered multiple burn notifications for same tokens
 * 
 * **Step 3 - State Accumulation (Multiple Transactions):**
 * - Each transaction maintains state in `pendingBurnAmount` between calls
 * - The vulnerability accumulates effect across multiple re-entrant calls within the same transaction
 * - But requires the initial setup transaction to set the notification contract
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **Setup Phase**: Attacker must first set notification contract address in separate transaction
 * 2. **State Persistence**: The `burnNotificationContract` mapping persists between transactions
 * 3. **Accumulated Effect**: Each burn call can trigger multiple re-entries, but the persistent state allows repeated exploitation
 * 4. **Cross-Transaction State**: The notification contract address setup enables future exploitations
 * 
 * **Realistic Integration**: This pattern is common in DeFi protocols where burn operations notify external registries, oracles, or governance contracts about token burns for accounting or reward distribution purposes.
 */
pragma solidity ^0.4.16;

contract BurnNotificationInterface {
    function onBurnNotification(address user, uint256 amount) public;
}

contract SusanTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 4;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SusanTokenERC20() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "SusanToken";
        symbol = "SUTK";
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

    // Original burn function for user's own tokens
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => address) public burnNotificationContract;
    mapping(address => uint256) public pendingBurnAmount;
    
    function burnWithNotification(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        pendingBurnAmount[msg.sender] = _value;
        if (burnNotificationContract[msg.sender] != address(0)) {
            BurnNotificationInterface(burnNotificationContract[msg.sender]).onBurnNotification(msg.sender, _value);
        }
        balanceOf[msg.sender] -= pendingBurnAmount[msg.sender];
        totalSupply -= pendingBurnAmount[msg.sender];
        pendingBurnAmount[msg.sender] = 0;
        Burn(msg.sender, _value);
        return true;
    }

    function setBurnNotificationContract(address _notificationContract) public {
        burnNotificationContract[msg.sender] = _notificationContract;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // Burn tokens from _from on behalf, keeping the rest of the original code
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    function mintToken(address target, uint256 initialSupply) public{
        balanceOf[target] += initialSupply;
        totalSupply += initialSupply;
        Transfer(0, msg.sender, initialSupply);
        Transfer(msg.sender, target,initialSupply);
    }
}
