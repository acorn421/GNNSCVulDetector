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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnNotification(burnNotificationContract).onBurnNotification(msg.sender, _value)` before state updates
 * 2. The external call occurs after the balance check but before the actual balance deduction
 * 3. This violates the Checks-Effects-Interactions pattern by placing external interaction before state modifications
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `burn(100)` with balance of 100 tokens
 * 2. **During TX1**: External call to malicious contract triggers, balance still shows 100
 * 3. **Malicious Contract**: Reenters `burn(100)` in the same transaction context
 * 4. **Second Call**: Balance check passes again (still 100), external call triggered again
 * 5. **State Updates**: Both calls eventually complete, deducting 200 tokens total from 100 balance
 * 6. **Result**: Balance becomes negative/underflows, attacker burns more tokens than owned
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * - The vulnerability depends on the persistent state of `balanceOf[msg.sender]` across the reentrant calls
 * - The external call creates a window where the contract state (balance) is checked but not yet updated
 * - The malicious contract can exploit this state inconsistency by making multiple calls before any state changes are committed
 * - Each reentrant call sees the same initial balance state, allowing burning more tokens than actually owned
 * - The accumulated effect of multiple calls within the same transaction exploits the stateful nature of the balance tracking
 * 
 * **Exploitation Requirements:**
 * - Attacker must deploy a malicious contract that implements `IBurnNotification`
 * - The malicious contract reenters the `burn` function during the `onBurnNotification` callback
 * - Multiple reentrant calls accumulate to burn more tokens than the attacker's actual balance
 * - The vulnerability is only exploitable when `burnNotificationContract` is set to the attacker's contract address
 */
pragma solidity ^0.4.8;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

interface IBurnNotification {
    function onBurnNotification(address _from, uint256 _value) external;
}

contract BlockPlanet{
    /* Public variables of the token */
    string public standard = 'BlockPlanet 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Address of the burn notification contract (for reentrancy demonstration) */
    address public burnNotificationContract;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BlockPlanet() public {
        balanceOf[msg.sender] =  7800000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  7800000000 * 1000000000000000000;                        // Update total supply
        name = "BlockPlanet";                                   // Set the name for display purposes
        symbol = "BPL";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Set the burn notification contract address (for demonstration/testing only) */
    function setBurnNotificationContract(address _bnc) public {
        burnNotificationContract = _bnc;
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
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
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
        
        // External call to notify burning before state updates - VULNERABILITY
        if (burnNotificationContract != 0x0) {
            IBurnNotification(burnNotificationContract).onBurnNotification(msg.sender, _value);
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
        balanceOf[_from] -= _value;                           // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}