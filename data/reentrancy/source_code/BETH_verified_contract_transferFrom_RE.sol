/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (if it's a contract) BEFORE updating the allowance state. This creates a window where the allowance hasn't been decremented yet, allowing the recipient contract to re-enter and exploit the stale allowance value across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious recipient contract
 *    - Balance updates happen correctly
 *    - External call to malicious recipient contract is made
 *    - Recipient contract can re-enter transferFrom or other functions
 *    - Allowance is still at original value during re-entrancy
 *    - Attacker can initiate additional transfers using the same allowance
 * 
 * 2. **Transaction 2+**: Through re-entrancy, attacker can:
 *    - Call transferFrom again with the same allowance value
 *    - Drain more tokens than originally approved
 *    - Each re-entrant call sees the allowance before it's decremented
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger re-entrancy
 * - State accumulation occurs as balances are modified but allowances aren't decremented until after the external call
 * - Multiple re-entrant calls can exploit the same allowance value
 * - The attack builds state across multiple function invocations within the same transaction context, but the vulnerability can also be exploited across separate transactions if the attacker can maintain the state discrepancy
 * 
 * This creates a realistic CEI (Checks-Effects-Interactions) pattern violation where the external interaction occurs before all state effects are finalized.
 */
pragma solidity ^0.4.8;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of token receipt - VULNERABLE: External call before allowance update
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        allowance[_from][msg.sender] -= _value;               // VULNERABLE: State update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) private constant returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
