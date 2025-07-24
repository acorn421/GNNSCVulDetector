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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordering State Updates**: Moved the recipient balance update before the external call, while keeping sender balance and allowance updates after the external call. This creates an inconsistent state during the external call.
 * 
 * 2. **Added External Call**: Introduced a call to `tokenRecipient(_to).receiveApproval()` that occurs after the recipient's balance is updated but before the sender's balance and allowance are decremented.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: 
 *    - **Transaction 1**: Attacker contract calls `transferFrom`, receives tokens (balance updated), then during the `receiveApproval` callback, it can call `transferFrom` again with the same allowance (since allowance hasn't been decremented yet). This second call will fail the balance check initially but sets up state for future exploitation.
 *    - **Transaction 2+**: Through accumulated state changes across multiple transactions, the attacker can exploit the window where balances are inconsistent with allowances, potentially draining tokens by repeatedly calling `transferFrom` in a sequence where each call builds upon the state changes from previous calls.
 * 
 * 4. **State Persistence**: The vulnerability relies on the persistent state changes to `balanceOf` and `allowance` mappings that accumulate across transactions, making it impossible to exploit in a single atomic transaction.
 * 
 * 5. **Realistic Integration**: The `receiveApproval` callback is a legitimate pattern for notifying recipients about token transfers, making this injection appear natural and not obviously malicious.
 * 
 * The vulnerability requires multiple transactions because the attacker needs to build up state changes across calls - each transaction contributes to the overall attack by manipulating the timing of state updates, and the full exploitation requires a sequence of operations that leverage the accumulated inconsistencies.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WenWanCoin {
    /* Public variables of the token */
    string public standard = 'WenWanCoin 0.1';
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
    function WenWanCoin() public {
        balanceOf[msg.sender] = 50000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 50000000 * 1000000000000000000;                        // Update total supply
        name = "WenWanCoin";                                   // Set the name for display purposes
        symbol = "WWC";                               // Set the symbol for display purposes
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
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // VULNERABILITY: External call to recipient before completing state updates
        // This allows recipient to re-enter with updated balance but unchanged allowance
        if (isContract(_to)) {
            tokenRecipient recipient = tokenRecipient(_to);
            recipient.receiveApproval(_from, _value, this, "");
        }
        
        // Critical state updates happen AFTER external call
        balanceOf[_from] -= _value;                           // Subtract from the sender
        allowance[_from][msg.sender] -= _value;               // Update allowance
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to detect if _addr is a contract
    function isContract(address _addr) internal returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
        return true;
    }
}
