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
 * Modified the transferFrom function to introduce a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Inserted a recipient notification callback before balance and allowance updates, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker gets approval for a large allowance amount
 *    - **Transaction 2**: Attacker calls transferFrom, which triggers the callback to their malicious contract
 *    - **During Callback**: The attacker can re-enter transferFrom multiple times using the same allowance before it's decremented
 *    - **Result**: Attacker drains more tokens than their allowance should permit
 * 
 * 3. **State Persistence Dependency**: The vulnerability depends on persistent state between transactions:
 *    - The allowance mapping persists between transactions
 *    - The attacker's malicious contract state persists between the initial call and reentrancy
 *    - The victim's balance state accumulates damage across multiple reentrant calls
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - Initial approval transaction must happen first to set up the allowance
 *    - The exploitation transaction triggers the callback which enables reentrancy
 *    - Multiple reentrant calls within the same transaction context drain funds progressively
 *    - Each reentrant call sees the same allowance value since it's not decremented until after the callback
 * 
 * 5. **Realistic Implementation**: The callback mechanism mimics real-world patterns like ERC777 hooks or notification systems, making this a realistic vulnerability that could appear in production code.
 * 
 * The vulnerability allows an attacker to drain significantly more tokens than their allowance permits by exploiting the timing window between the external call and the allowance decrement, requiring careful setup across multiple transactions to be effective.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

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
    function WoNiuBi() public {
        balanceOf[msg.sender] =  3681391186 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  3681391186 * 1000000000000000000;                        // Update total supply
        name = "WoNiuBi";                                   // Set the name for display purposes
        symbol = "WNB";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state changes - allows for reentrancy
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            tokenRecipient recipient = tokenRecipient(_to);
            recipient.receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }
}