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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first approve allowance in one transaction, then exploit the vulnerability in subsequent transactions.
 * 
 * 2. **State Persistence**: The allowance state persists between transactions, allowing the attacker to repeatedly exploit the same allowance approval.
 * 
 * 3. **External Call Before State Update**: The external call to `recipient.receiveApproval()` occurs before the critical state update `allowance[_from][msg.sender] -= _value`, violating the checks-effects-interactions pattern.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Victim approves allowance of 1000 tokens to attacker
 * - **Transaction 2**: Attacker calls transferFrom(victim, maliciousContract, 1000) 
 * - **During Transaction 2**: The external call to maliciousContract.receiveApproval() is made BEFORE allowance is decremented
 * - **Reentrancy Attack**: The malicious contract re-enters transferFrom() with the same allowance still available (1000 tokens), allowing it to drain more tokens than intended
 * - **Result**: Attacker can potentially drain much more than the originally approved 1000 tokens
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires pre-existing allowance approval (setup transaction)
 * - The exploit depends on the persistent allowance state from previous transactions
 * - Cannot be exploited in a single atomic transaction without prior allowance setup
 * - The reentrancy window exists because allowance state is not updated until after the external call
 * 
 * This creates a realistic vulnerability that requires accumulated state (allowance) from previous transactions to be exploitable.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract ShanHuCoin {
    /* Public variables of the token */
    string public standard = 'ShanHuCoin 0.1';
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
    function ShanHuCoin() public {
        balanceOf[msg.sender] = 11000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 11000000 * 1000000000000000000;                        // Update total supply
        name = "ShanHuCoin";                                   // Set the name for display purposes
        symbol = "SHC";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (external call before state update)
        if (isContract(_to)) {
            tokenRecipient recipient = tokenRecipient(_to);
            recipient.receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;               // Update allowance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
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