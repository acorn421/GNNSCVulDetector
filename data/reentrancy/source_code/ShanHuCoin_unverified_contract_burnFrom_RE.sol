/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase burn process. The vulnerability requires:
 * 
 * 1. **State Persistence**: Added `burnRequests` mapping to track burn requests between transactions
 * 2. **Multi-Transaction Requirement**: Split burn into two phases - initiation and completion
 * 3. **External Call Before State Update**: In the first transaction, an external call to `receiveApproval` is made before any state changes
 * 4. **Reentrancy Window**: During the external call in the first transaction, the attacker can re-enter and manipulate the burn process
 * 
 * **Exploitation Process:**
 * - Transaction 1: Attacker calls burnFrom, which triggers external call but only sets burnRequests state
 * - During external call: Attacker can re-enter and call burnFrom again, exploiting the fact that balanceOf hasn't been updated yet
 * - Transaction 2: Attacker completes the burn process, but may have already exploited inconsistent state
 * 
 * **Multi-Transaction Nature:**
 * - The vulnerability cannot be exploited in a single transaction due to the two-phase design
 * - State accumulation (burnRequests) is required between transactions
 * - The external call in the first phase creates a reentrancy window that can be exploited across multiple calls
 * - Each phase checks different state conditions, creating opportunities for state manipulation between transactions
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

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
    
    // Added missing mapping for burnRequests to fix undeclared identifier errors
    mapping (address => mapping (address => uint256)) public burnRequests;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ShanHuCoin() {
        balanceOf[msg.sender] = 11000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 11000000 * 1000000000000000000;                        // Update total supply
        name = "ShanHuCoin";                                   // Set the name for display purposes
        symbol = "SHC";                               // Set the symbol for display purposes
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
        
        // Multi-stage burn process for compliance tracking
        if (burnRequests[_from][msg.sender] == 0) {
            // First transaction: initiate burn request
            burnRequests[_from][msg.sender] = _value;
            
            // Notify burn recipient about pending burn (external call before state update)
            if (_from != msg.sender) {
                tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
            }
            
            return true;
        } else {
            // Second transaction: complete burn after notification
            uint256 requestedAmount = burnRequests[_from][msg.sender];
            if (requestedAmount != _value) throw;
            
            // State updates after external call sequence
            balanceOf[_from] -= _value;                          // Subtract from the sender
            totalSupply -= _value;                               // Updates totalSupply
            burnRequests[_from][msg.sender] = 0;                 // Clear burn request
            
            Burn(_from, _value);
            return true;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}
