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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Introduction**: Added a callback to the _from address (if it's a contract) before state updates, using the existing tokenRecipient interface for realistic integration.
 * 
 * 2. **State Persistence**: The vulnerability exploits persistent state across multiple transactions:
 *    - balanceOf and totalSupply are checked initially but modified after the external call
 *    - allowance state persists between transactions and is only reduced after the external call
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker sets up allowance using approve()
 *    - Transaction 2: Attacker calls burnFrom() which triggers the callback
 *    - During callback: Attacker can reenter burnFrom() because balanceOf hasn't been updated yet
 *    - The reentrancy exploits stale state from previous transactions
 * 
 * 4. **Stateful Nature**: The vulnerability requires accumulated state from previous transactions (allowance setup) and exploits the fact that state changes persist between calls, enabling the attacker to drain more tokens than they should be able to.
 * 
 * 5. **Realistic Integration**: The callback mechanism mimics legitimate "burn notification" functionality commonly found in token contracts, making the vulnerability subtle and realistic.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract KuangJinLian{
    /* Public variables of the token */
    string public standard = 'JinKuangLian 0.1';
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
    function KuangJinLian() public {
        balanceOf[msg.sender] =  1200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1200000000 * 1000000000000000000;                        // Update total supply
        name = "KuangJinLian";                                   // Set the name for display purposes
        symbol = "KJL";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder before burning - introduces external call
        uint256 size;
        assembly { size := extcodesize(_from) }
        if (size > 0) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn_notification");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(_from, _value);
        return true;
    }
}
