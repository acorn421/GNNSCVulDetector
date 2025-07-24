/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Injection**: Added an external call to `tokenRecipient(_from).receiveApproval()` that notifies the burn target if it's a contract. This call happens after balance and totalSupply updates but before allowance reduction.
 * 
 * 2. **State Modification Order**: Moved the allowance reduction to occur AFTER the external call, creating a window where the allowance is not yet consumed but balances are already updated.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `burnFrom` with a contract as `_from` that implements `receiveApproval`. During the external call, the contract can reenter and call `burnFrom` again with the same allowance since it hasn't been reduced yet.
 *    - **Transaction 2**: The reentrant call succeeds because the allowance check passes (allowance not yet reduced), but the balance check also passes due to the specific timing of state updates.
 *    - **Cumulative Effect**: Multiple burns can be executed with the same allowance value, allowing burning more tokens than the allowance should permit.
 * 
 * 4. **Stateful Dependency**: The vulnerability requires:
 *    - Setting up an allowance in a previous transaction
 *    - Deploying a malicious contract that implements `receiveApproval`
 *    - The attack accumulates across multiple reentrant calls within the same transaction, but the setup requires multiple transactions to establish the allowance and deploy the attacking contract.
 * 
 * 5. **Realistic Integration**: The notification mechanism appears legitimate - notifying contract holders about burns is a reasonable feature that could exist in production token contracts.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 1. **Setup Transaction**: Attacker gets allowance approval from victim
 * 2. **Attack Transaction**: Attacker calls `burnFrom` with malicious contract as `_from`
 * 3. **Reentrant Exploitation**: During `receiveApproval` callback, the malicious contract reenters `burnFrom` multiple times before the allowance is reduced
 * 4. **Result**: More tokens burned than the allowance should permit, potentially draining the victim's balance
 * 
 * The vulnerability is stateful because it depends on the allowance state established in previous transactions and exploits the timing between balance updates and allowance reduction across multiple nested calls.
 */
pragma solidity ^0.4.6;
contract tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract JackToken {
    /* Public variables of the Jack Currency*/
    string public standard = 'Jack 1.0';
    string public name = 'JackCurrency';
    string public symbol = 'JACK';
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
    function JackToken() {
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
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

	/* Burn Jack by User */
    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                         // Subtract from the sender
        totalSupply -= _value;                                   // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

	/* Burn Jack from Users */
    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update state before external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                             // Subtract from the sender
        totalSupply -= _value;                                  // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call that enables reentrancy - notify burn recipient if it's a contract
        if (isContract(_from)) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // Critical: allowance reduction happens AFTER external call
        allowance[_from][msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
    
    // Helper function to check if an address is a contract (for pre-0.5.0)
    function isContract(address _addr) private constant returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
