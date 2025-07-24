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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability allows a malicious recipient contract to exploit the inconsistent state across multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` before state updates
 * 2. The call invokes `onTokenReceived()` on the recipient contract
 * 3. State modifications (balanceOf, allowance) occur AFTER the external call
 * 4. The call continues regardless of success to maintain functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls transferFrom() to their malicious contract
 * 2. **During Transaction 1**: The malicious contract's onTokenReceived() is called before state updates
 * 3. **Malicious Contract Action**: The contract can call transferFrom() again while original state is unchanged
 * 4. **Transaction 2+**: Subsequent calls exploit the fact that balances haven't been updated yet
 * 5. **State Accumulation**: Multiple reentrancy calls can drain more tokens than originally allowed
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to set up allowances in previous transactions
 * - The malicious contract must be deployed and configured beforehand
 * - The exploit accumulates state changes across multiple nested calls within the same transaction call stack
 * - The allowance mechanism creates dependencies on prior transaction state
 * - Full exploitation requires multiple transferFrom calls to drain significant funds
 * 
 * **Realistic Nature:**
 * - Transfer notifications to recipient contracts are common in modern tokens
 * - The pattern appears legitimate for DeFi integration
 * - Backward compatibility preservation makes it seem like careful coding
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract AdvancedArtificialIntelligenceSafetyDefense{
    /* Public variables of the token */
    string public standard = 'AdvancedArtificialIntelligenceSafetyDefense 0.1';
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
    function AdvancedArtificialIntelligenceSafetyDefense() {
        balanceOf[msg.sender] =  960000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  960000000 * 1000000000000000000;                        // Update total supply
        name = "AdvancedArtificialIntelligenceSafetyDefense";                                   // Set the name for display purposes
        symbol = "AISD";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates - creates reentrancy opportunity
        if (isContract(_to)) {
            // Call to recipient contract for transfer notification
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of call success to maintain backward compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;               // Update allowance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    // Internal function to check if an address is a contract (for pre-0.5.0)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}