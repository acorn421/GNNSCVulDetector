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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. This violates the Checks-Effects-Interactions pattern and creates a realistic callback mechanism that allows for cross-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value)` before the state updates
 * 2. The external call occurs after the balance check but before the actual balance and totalSupply modifications
 * 3. This creates a window where an attacker can re-enter the burn function with stale state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements IBurnNotification and sets it as the burnNotificationContract
 * **Transaction 2 (Exploit)**: Attacker calls burn() with maximum available balance:
 *    - burn() checks attacker has sufficient balance (passes)
 *    - External call to malicious contract triggers notifyBurn()
 *    - Malicious contract re-enters burn() before state is updated
 *    - Second burn() call sees the same unchanged balance and passes the check
 *    - Both burn operations complete, burning more tokens than the attacker owned
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Preparation**: The attacker must first set up the malicious notification contract in a separate transaction
 * 2. **Accumulated State Manipulation**: The vulnerability exploits the fact that state changes persist between the setup transaction and the exploit transaction
 * 3. **Cross-Transaction Reentrancy**: The malicious contract established in Transaction 1 enables the reentrancy attack in Transaction 2
 * 4. **Persistent State Corruption**: The exploit leaves the contract in an inconsistent state that affects all future operations
 * 
 * **Realistic Integration**: Adding a burn notification system is a common pattern in DeFi tokens for ecosystem integration, making this vulnerability subtle and realistic while maintaining the original function's core behavior.
 */
pragma solidity ^0.4.8;

interface IBurnNotification {
    function notifyBurn(address from, uint256 value) external;
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BETH {
    /* Public variables of the token */
    string public standard = 'BETH';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Address of the burn notification contract */
    address public burnNotificationContract;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BETH() {
        balanceOf[msg.sender] =  2100000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  2100000 * 1000000000000000000;                        // Update total supply
        name = "BETH";                                   // Set the name for display purposes
        symbol = "B.ETH";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Set the burn notification contract address */
    function setBurnNotificationContract(address _contract) public {
        burnNotificationContract = _contract;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add burn notification callback system for ecosystem integration
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
