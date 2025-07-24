/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn registry before state updates. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **External Call Before State Changes**: Added call to `IBurnRegistry(burnRegistry).onBurnNotification(msg.sender, _value)` before balance and totalSupply updates
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit effectively:
 *    - Transaction 1: User initiates burn, external call allows reentrancy
 *    - Reentrant Calls: Multiple burn operations using the same balance before state updates
 *    - State Accumulation: Each reentrant call reduces totalSupply multiple times for the same burned tokens
 * 
 * 3. **Stateful Nature**: The vulnerability depends on persistent state (balanceOf and totalSupply) that accumulates damage across multiple reentrant calls
 * 
 * 4. **Realistic Integration**: The burn registry notification is a realistic feature that could appear in production code for tracking burn events, oracle updates, or compliance reporting
 * 
 * **Exploitation Sequence:**
 * - User has 1000 tokens and calls burn(1000)
 * - External call to burnRegistry triggers reentrancy
 * - Reentrant call: burn(1000) again with same balance (still 1000)
 * - Multiple reentrant calls possible before state updates
 * - Result: totalSupply reduced by 1000 multiple times, but user's balance only reduced once
 * - Token economics broken with inflated burn amounts vs actual burned tokens
 * 
 * The vulnerability is only exploitable through multiple function calls and cannot be triggered in a single atomic transaction, making it a genuine multi-transaction, stateful vulnerability.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

interface IBurnRegistry {
    function onBurnNotification(address _from, uint256 _value) external;
}

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

    /* Address of the burn registry contract */
    address public burnRegistry; // Added missing variable declaration

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
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify burn registry - VULNERABILITY INJECTION POINT
        if (burnRegistry != address(0)) {
            IBurnRegistry(burnRegistry).onBurnNotification(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        return true;
    }
}
