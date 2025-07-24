/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient's `tokensReceived` callback function before state updates. This follows the violation of the Checks-Effects-Interactions pattern, where external calls are made before critical state changes (balance and allowance updates).
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls `approve()` to grant allowance to a malicious contract
 * 2. **Transaction 2 (Exploitation)**: Malicious contract calls `transferFrom()`, which triggers the `tokensReceived` callback
 * 3. **During Callback**: The callback function calls `transferFrom()` again before the first call's state updates complete
 * 4. **State Persistence**: The allowance and balance checks pass multiple times because state isn't updated until after the callback
 * 
 * **Why Multi-Transaction is Required:**
 * - Initial allowance must be set up in a separate transaction via `approve()`
 * - The reentrancy exploit requires the callback mechanism to be triggered during `transferFrom()`
 * - Multiple calls to `transferFrom()` are needed to drain more funds than initially allowed
 * - The vulnerability exploits the persistent state of allowances and balances across transaction boundaries
 * 
 * **Exploitation Scenario:**
 * 1. Attacker approves malicious contract for 100 tokens
 * 2. Malicious contract calls `transferFrom()` for 100 tokens
 * 3. During the `tokensReceived` callback, it calls `transferFrom()` again for another 100 tokens
 * 4. Both calls pass the allowance check because the allowance hasn't been decremented yet
 * 5. Attacker drains 200 tokens while only having approval for 100
 * 
 * This creates a realistic vulnerability that mirrors real-world reentrancy issues in token contracts with callback mechanisms.
 */
/****/
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract JinKuangLian{
    string public standard = 'JinKuangLian 0.1';
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
    function JinKuangLian() {
        balanceOf[msg.sender] =  1200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1200000000 * 1000000000000000000;                        // Update total supply
        name = "JinKuangLian";                                   // Set the name for display purposes
        symbol = "JKL";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call before state updates - allows reentrancy
        // Check if recipient has a callback function and call it before updating state
        uint256 recipientCodeSize;
        assembly {
            recipientCodeSize := extcodesize(_to)
        }
        if (recipientCodeSize > 0) {
            // Call recipient's tokensReceived callback if it exists
            bool callSuccess;
            bytes memory callData = abi.encodeWithSignature("tokensReceived(address,address,uint256)", _from, _to, _value);
            assembly {
                callSuccess := call(gas(), _to, 0, add(callData, 0x20), mload(callData), 0, 0)
            }
            // Continue regardless of callback success/failure
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}