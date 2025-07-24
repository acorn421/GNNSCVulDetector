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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token owner before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **CHANGES MADE:**
 * 1. Added external call to `_from.call()` before state modifications
 * 2. Added explicit allowance reduction (missing in original)
 * 3. External call allows reentrancy into contract functions
 * 
 * **MULTI-TRANSACTION EXPLOITATION SEQUENCE:**
 * 1. **Transaction 1 (Setup)**: Attacker contract calls `approve()` to grant allowance to itself
 * 2. **Transaction 2 (Exploit)**: Attacker calls `burnFrom()` on a contract that implements `onTokenBurn()`
 *    - During `onTokenBurn()` callback, the attacker can re-enter `burnFrom()` or other functions
 *    - Initial checks pass but state changes haven't occurred yet
 *    - Attacker can drain tokens by calling `burnFrom()` multiple times before state updates
 * 3. **Transaction 3+ (Continuation)**: Additional calls can exploit the inconsistent state
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * - Transaction 1 is needed to establish allowance state
 * - Transaction 2 triggers the vulnerability through the callback mechanism
 * - The allowance system creates persistent state between transactions
 * - Each reentrancy call during the callback can exploit the same allowance multiple times
 * - The vulnerability leverages state persistence across transaction boundaries
 * 
 * **STATEFUL NATURE:**
 * - Allowance state persists between transactions
 * - Balance state carries over between calls
 * - The external call creates a window where state is inconsistent across multiple function invocations
 * - Exploitation requires accumulated state from previous approve() calls
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BlessingChainAlliance{
    /* Public variables of the token */
    string public standard = 'BlessingChainAlliance 0.1';
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
    function BlessingChainAlliance() {
        balanceOf[msg.sender] =  200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  200000000 * 1000000000000000000;                        // Update total supply
        name = "BlessingChainAlliance";                                   // Set the name for display purposes
        symbol = "BCA";                               // Set the symbol for display purposes
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
        
        // External call to notify the token owner before burning (VULNERABILITY INJECTION)
        if (_from != msg.sender) {
            // Call an external contract to notify about the burn
            (bool callSuccess, ) = _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}