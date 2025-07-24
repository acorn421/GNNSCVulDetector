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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This allows the recipient to re-enter transferFrom during the callback, exploiting the fact that balances and allowances haven't been updated yet. The vulnerability is multi-transaction because:
 * 
 * 1. **Transaction 1**: Attacker sets up allowance and deploys malicious contract
 * 2. **Transaction 2**: Legitimate user calls transferFrom to malicious contract
 * 3. **During Transaction 2**: Malicious contract re-enters transferFrom in its receiveApproval callback
 * 4. **Exploitation**: Since balances/allowances aren't updated until after the callback, the attacker can drain funds multiple times
 * 
 * The vulnerability requires persistent state (allowances set in previous transactions) and multiple function calls to be exploitable, making it a genuine stateful, multi-transaction security flaw.
 */
/* Create by www.hestart.com */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract SpaceChain {
    /* Public variables of the token */
    string public standard = 'SpaceChain 0.1';
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
    constructor() public {
        balanceOf[msg.sender] =  1000000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1000000000000 * 1000000000000000000;                        // Update total supply
        name = "SpaceChain";                                   // Set the name for display purposes
        symbol = "Schain";                               // Set the symbol for display purposes
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable: External call to recipient before state updates
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Call recipient's onTokenReceived callback if it's a contract
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
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
