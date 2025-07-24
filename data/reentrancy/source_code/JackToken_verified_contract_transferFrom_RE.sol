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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Completion**: Inserted a callback to the recipient contract (`tokenRecipient(_to).receiveApproval()`) after balance updates but before allowance reduction.
 * 
 * 2. **State Inconsistency Window**: The allowance is only reduced AFTER the external call, creating a window where balances are updated but allowance remains unchanged.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls transferFrom with malicious recipient contract
 *    - **During callback**: Recipient can re-enter transferFrom (or other functions) while allowance is still unreduced
 *    - **Transaction 2**: Subsequent calls exploit the inconsistent allowance/balance state
 *    - **State Accumulation**: Each transaction builds on the previous state inconsistencies
 * 
 * 4. **Realistic Integration**: Uses the existing `tokenRecipient` interface and `receiveApproval` function, making it appear as a legitimate transfer notification feature.
 * 
 * 5. **Persistent State Vulnerability**: The allowance state persists between transactions, enabling gradual exploitation where an attacker can:
 *    - Build up allowance credits across multiple transactions
 *    - Exploit timing differences between balance updates and allowance reductions
 *    - Use accumulated state inconsistencies for profit extraction
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - TX1: transferFrom called → balances updated → callback triggered → allowance still high
 * - During callback: Re-enter with different parameters while allowance unchanged  
 * - TX2: Use accumulated allowance credits from previous incomplete state updates
 * - TX3: Repeat pattern to drain funds progressively
 * 
 * This creates a realistic vulnerability that requires orchestrated multi-transaction attacks and cannot be exploited atomically in a single transaction.
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
    function JackToken() public {
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens on my behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        if ((_value != 0) && (allowance[msg.sender][_spender] != 0)) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
        returns (bool success) {
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
        balanceOf[_from] -= _value;                              // Subtract from the sender
        balanceOf[_to] += _value;                                // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about the transfer (potential callback)
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        allowance[_from][msg.sender] -= _value;                  // Update allowance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    /* Util: check if address is contract */
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

	/* Burn Jack by User */
    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                         // Subtract from the sender
        totalSupply -= _value;                                   // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

	/* Burn Jack from Users */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                             // Subtract from the sender
        totalSupply -= _value;                                  // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
