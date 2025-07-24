/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism after the user's balance is reduced but before the totalSupply is updated. This creates a window where the contract state is inconsistent, and an attacker can exploit this through multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnCallback(burnCallback).onTokenBurn()` after the balance reduction
 * 2. The external call occurs before the totalSupply is updated, creating a state inconsistency window
 * 3. The burnCallback address would need to be set via a separate setter function (assumed to exist)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls burn() which reduces their balance but triggers the external callback
 * Transaction 2: During the callback, the attacker can re-enter through other functions (like transfer, approve, etc.) while their balance appears reduced but totalSupply hasn't been updated yet
 * Transaction 3: The attacker can exploit this inconsistent state to manipulate token accounting
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the burnCallback address to be set in a previous transaction
 * - The attacker needs to deploy a malicious callback contract in advance
 * - The exploitation depends on the persistent state changes (balance reduction) that occur across transaction boundaries
 * - The callback mechanism creates a stateful dependency that persists between function calls
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

interface IBurnCallback {
    function onTokenBurn(address from, uint256 value) external;
}

contract FuckToken {
    /* Public variables of the FUCK token */
    string public standard = 'FUCK 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* Creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* burnCallback address for external notification in burn() */
    address public burnCallback;

    /* Generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to me */
    function FuckToken(uint256 initialSupply, string tokenName, uint8 decimalUnits, string tokenSymbol) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens on my behalf */
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

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify burn callback before completing burn process
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onTokenBurn(msg.sender, _value);
        }
        totalSupply -= _value;                                // Updates totalSupply after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
    
    function giveBlockReward() public {
        balanceOf[block.coinbase] += 70000;
    }

    /* Optional: Function to set the burnCallback address */
    function setBurnCallback(address _callback) public {
        burnCallback = _callback;
    }
}
