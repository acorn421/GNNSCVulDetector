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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burn handler before state updates. This creates a vulnerability pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnHandler(burnHandler).onPreBurn(msg.sender, _value)` before the state updates
 * 2. The call happens after the balance check but before the actual balance and totalSupply modifications
 * 3. This assumes a `burnHandler` state variable exists that can be set to a user-controlled contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker sets `burnHandler` to their malicious contract address
 * 2. **Transaction 2 (Initial Burn)**: Attacker calls `burn()` with amount X:
 *    - Balance check passes
 *    - External call to attacker's contract triggers
 *    - Attacker's contract can call `burn()` again recursively
 *    - Inner `burn()` call sees the same original balance (state not yet updated)
 *    - Inner call passes balance check and completes, reducing balance by X
 *    - Original call continues and reduces balance by X again
 *    - Result: Balance reduced by 2X, but totalSupply potentially inconsistent
 * 3. **Transaction 3+ (Exploitation)**: Attacker can leverage the inconsistent state between balance and totalSupply for further exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the attacker first setting up the malicious burnHandler in a separate transaction
 * - The exploit requires the external call to trigger reentrancy that depends on the current state
 * - The accumulated effects across multiple burns create compounding inconsistencies
 * - The attacker needs multiple calls to fully exploit the state inconsistencies between balanceOf and totalSupply
 * 
 * **Stateful Nature:**
 * - The vulnerability persists across transactions via the burnHandler state variable
 * - Each burn operation affects the persistent balanceOf and totalSupply mappings
 * - The exploit compounds with each additional burn transaction
 * - The inconsistent state created in earlier transactions enables exploitation in later ones
 */
pragma solidity ^0.4.8;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Interface for the burn handler (to preserve vulnerability code)
interface IBurnHandler {
    function onPreBurn(address from, uint256 value) external;
}

contract GoodGame {
    /* Public variables of the token */
    string public standard = 'GoodGame 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    // Added variable for burn handler
    address public burnHandler;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function GoodGame() public {
        balanceOf[msg.sender] =  10000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  10000000000 * 1000000000000000000;                        // Update total supply
        name = "GoodGame";                                   // Set the name for display purposes
        symbol = "GG";                               // Set the symbol for display purposes
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
        // Notify external burn handler before state changes
        if (burnHandler != address(0)) {
            IBurnHandler(burnHandler).onPreBurn(msg.sender, _value);
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
