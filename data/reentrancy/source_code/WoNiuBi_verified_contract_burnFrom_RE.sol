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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates occur. This violates the checks-effects-interactions pattern and enables the following multi-transaction exploitation scenario:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract implementing IBurnNotification
 * - Attacker obtains tokens and sets up allowances for the exploit
 * 
 * **Transaction 2 (Exploitation):**
 * - Authorized spender calls burnFrom on attacker's malicious contract
 * - During the onBurnFrom callback, the malicious contract re-enters burnFrom
 * - Since balanceOf and allowance haven't been updated yet, the same tokens can be burned multiple times
 * - Each reentrant call reads stale state values, allowing excessive burning
 * 
 * **Multi-Transaction Nature:**
 * - Requires separate transactions to set up the malicious contract and allowances
 * - State from previous transactions (balances, allowances) is crucial for exploitation
 * - The vulnerability cannot be exploited in a single transaction without prior state setup
 * - Accumulated state changes from setup transactions enable the reentrancy attack
 * 
 * The external call is made to _from before state updates, creating a classic reentrancy vulnerability that depends on persistent state accumulated across multiple transactions.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Add missing interface for IBurnNotification to support the external call
interface IBurnNotification {
    function onBurnFrom(address from, uint256 value);
}

contract WoNiuBi{
    /* Public variables of the token */
    string public standard = 'WoNiuBi 0.1';
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

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function WoNiuBi() {
        balanceOf[msg.sender] =  3681391186 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  3681391186 * 1000000000000000000;                        // Update total supply
        name = "WoNiuBi";                                   // Set the name for display purposes
        symbol = "WNB";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
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
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call to notify the token holder before state changes
        // This creates a reentrancy vulnerability
        // In Solidity 0.4.x, there is no code.length or try/catch. Instead, we check if it's a contract by extcodesize()
        uint codeLength;
        assembly { codeLength := extcodesize(_from) }
        if (codeLength > 0) {
            IBurnNotification(_from).onBurnFrom(msg.sender, _value);
            // external call, proceed regardless of success/failure
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}