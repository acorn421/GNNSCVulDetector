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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnCallback(burnCallback).onBurnNotification(msg.sender, _value)` before state updates
 * 2. The callback occurs after balance validation but before balance subtraction
 * 3. This creates a window where the attacker's balance is still intact during the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious callback contract implementing IBurnCallback
 * - Attacker calls admin function to set burnCallback to their malicious contract
 * - Attacker obtains some tokens (via transfer or initial allocation)
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Attacker calls burn() with their full balance
 * - Function validates balance (passes check)
 * - External call triggers attacker's onBurnNotification()
 * - In callback, attacker calls transfer() to move tokens to another account
 * - Since balanceOf[attacker] hasn't been updated yet, transfer succeeds
 * - Original burn() continues and reduces already-transferred balance
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Attacker repeats the process with the receiving account
 * - Each iteration allows burning more tokens than actually owned
 * - The totalSupply becomes corrupted across multiple transactions
 * - State inconsistency persists between transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **Setup Phase**: Attacker must first deploy callback contract and get it registered
 * 2. **State Accumulation**: Each burn call creates temporary state inconsistency that can be exploited
 * 3. **Persistent Corruption**: The totalSupply corruption accumulates across multiple burn operations
 * 4. **Cannot be Atomic**: The exploit requires the external callback to perform additional contract calls (transfer, approve) during the reentrancy window
 * 
 * **Key State Variables Affected:**
 * - `balanceOf[msg.sender]` - temporarily inconsistent during external call
 * - `totalSupply` - permanently corrupted after each successful exploit
 * - External account balances - manipulated through reentrancy window
 * 
 * The vulnerability is realistic as notification callbacks are common in DeFi protocols for integration with external systems, analytics, or governance mechanisms.
 */
pragma solidity ^0.4.8;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Interface for burn callback
interface IBurnCallback {
    function onBurnNotification(address from, uint256 value) external;
}

contract ISE {
    /* Public variables of the token */
    string public standard;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Optional burn callback address */
    address public burnCallback;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        balanceOf[msg.sender] =  1000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1000000000 * 1000000000000000000;                        // Update total supply
        standard = "ERC20";
        name = "ISE";                                   // Set the name for display purposes
        symbol = "ISE";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify burn callback before state updates
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onBurnNotification(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
