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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Changes Made:**
 * 1. Added an external call to `tokenRecipient(_from).receiveApproval()` before state updates
 * 2. Added allowance reduction (`allowance[_from][msg.sender] -= _value`) after the external call
 * 3. The external call occurs after validation but before critical state changes
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract approves itself with a large allowance
 * - Attacker calls `burnFrom()` on their own contract address
 * - During the external call (`receiveApproval`), the attacker's contract can see that:
 *   - Original allowance is still intact (not yet reduced)
 *   - Original balance is still intact (not yet reduced)
 *   - But the burn operation is in progress
 * 
 * **Transaction 2 (Exploitation):**
 * - During the reentrancy callback, attacker calls `burnFrom()` again
 * - The checks pass because the state hasn't been updated yet from Transaction 1
 * - This allows burning more tokens than the allowance should permit
 * - The attacker can repeat this pattern to drain more tokens than authorized
 * 
 * **Transaction 3+ (Accumulation):**
 * - Each subsequent reentrant call exploits the inconsistent state
 * - The persistent allowance and balance state from previous transactions enables continued exploitation
 * - The attacker can accumulate unauthorized burns across multiple nested calls
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability relies on allowance and balance state persisting between function calls
 * 2. **Accumulated Effect**: Each reentrant call exploits the same stale state, creating cumulative unauthorized burns
 * 3. **Cross-Call Dependencies**: The exploit depends on the sequence of external calls and state updates across multiple function invocations
 * 4. **Reentrancy Chain**: The vulnerability requires a chain of reentrant calls, each building on the persistent state from previous calls
 * 
 * **Realistic Scenario**: 
 * This simulates a common pattern where tokens notify holders before burning (for governance or logging purposes), but the notification mechanism creates a reentrancy window that can be exploited across multiple transactions to bypass allowance limits and burn more tokens than authorized.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BusinessTokenCoin {
    /* Public variables of the token */
    string public standard = 'BusinessTokenCoin 0.1';
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
    function BusinessTokenCoin() public {
        balanceOf[msg.sender] =  2100000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  2100000000 * 1000000000000000000;                        // Update total supply
        name = "BusinessTokenCoin";                                   // Set the name for display purposes
        symbol = "BTC";                               // Set the symbol for display purposes
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
        // Notify burn registry before state changes (VULNERABILITY: external call before state update)
        if (isContract(_from)) {
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

    // Utility function for contract detection, since .code is unavailable in Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool)
    {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
