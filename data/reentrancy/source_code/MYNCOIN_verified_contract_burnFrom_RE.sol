/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Inserted an external call to `IBurnNotifier(_from).onBurnFrom()` after the burn operations but before updating the allowance.
 * 
 * 2. **Delayed Allowance Update**: Moved the allowance update to occur AFTER the external call, creating a window where the allowance hasn't been decremented yet.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker contract calls `burnFrom()` with legitimate parameters
 *    - **During External Call**: The attacker's contract receives the `onBurnFrom` callback and can re-enter `burnFrom()` again
 *    - **Transaction 2** (via reentrancy): Since allowance hasn't been updated yet, the attacker can call `burnFrom()` again with the same allowance, effectively burning more tokens than they should be allowed to
 * 
 * 4. **Stateful Vulnerability**: The vulnerability depends on the persistent state of the allowance mapping between transactions. The attacker can exploit the fact that their allowance appears unchanged during the external call window.
 * 
 * 5. **Realistic Integration**: The external call pattern is common in DeFi protocols for implementing hooks and notifications, making this a realistic vulnerability that could appear in production code.
 * 
 * **Exploitation Scenario**:
 * - Alice approves Bob's contract for 1000 tokens
 * - Bob calls `burnFrom(alice, 1000)` 
 * - During the `onBurnFrom` callback, Bob's contract re-enters and calls `burnFrom(alice, 1000)` again
 * - Since allowance hasn't been updated yet, the second call succeeds
 * - Result: 2000 tokens burned but only 1000 allowance was consumed
 * 
 * This vulnerability requires multiple function calls (the initial call and the reentrant call) and depends on the persistent state of the allowance mapping between these calls.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

interface IBurnNotifier {
    function onBurnFrom(address burner, uint256 amount) external;
}

contract MYNCOIN {
    /* Public variables of the token */
    string public standard = 'MYN COIN ';
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
    function MYNCOIN() public {
        balanceOf[msg.sender] =  40000000 * 100000000;              // Give the creator all initial tokens
        totalSupply =  40000000 * 100000000;                        // Update total supply
        name = "MYN COIN";                                   // Set the name for display purposes
        symbol = "MYN";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
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

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn registry about the burn - external call before allowance update
        if (isContract(_from)) {
            IBurnNotifier(_from).onBurnFrom(msg.sender, _value);
        }
        
        // Update allowance after external call - VULNERABLE TO REENTRANCY
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    // Helper function to detect contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
