/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to tokenRecipient.receiveApproval() after balance updates but before the Transfer event. This creates a classic reentrancy scenario where:
 * 
 * 1. **State Modification Before External Call**: Balances are updated before the external call, creating an inconsistent state window
 * 2. **External Call to User-Controlled Contract**: The call to tokenRecipient(_to).receiveApproval() allows the recipient to execute arbitrary code
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to be effective:
 *    - **Transaction 1**: Attacker deploys malicious contract that implements receiveApproval()
 *    - **Transaction 2**: Victim transfers tokens to malicious contract, triggering receiveApproval()
 *    - **During Transaction 2**: Malicious contract's receiveApproval() calls transfer() again, exploiting the state inconsistency
 *    - **Subsequent Transactions**: Attacker can repeat the process to drain funds incrementally
 * 
 * **Multi-Transaction Nature**: The vulnerability cannot be exploited in a single transaction because:
 * - Attacker must first deploy and set up the malicious contract
 * - Multiple transfers are needed to accumulate significant value
 * - Each reentrancy call processes legitimate transfers, requiring fresh victim interactions
 * - The exploit builds on persistent state changes across multiple contract interactions
 * 
 * **Realistic Integration**: The callback mechanism is a common pattern in token contracts for notifying recipients, making this vulnerability realistic and subtle.
 */
pragma solidity ^0.4.6;
contract tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract IloveYou {
    /* Public variables of the Jack Currency*/
    string public standard = 'Donny 1.0';
    string public name = 'DonnyIloveMandy';
    string public symbol = 'DONLOVE';
    uint8 public decimals = 8;
    uint256 public totalSupply = 10000000000000000;

    /* Creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to me */
    function IloveYou() {
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update balances before external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify recipient - VULNERABLE: allows reentrancy
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(msg.sender, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    /* Allow another contract to spend some tokens on my behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if ((_value != 0) && (allowance[msg.sender][_spender] != 0)) revert();
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                              // Subtract from the sender
        balanceOf[_to] += _value;                                // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    /* Burn Dony by User */
    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                         // Subtract from the sender
        totalSupply -= _value;                                   // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

}