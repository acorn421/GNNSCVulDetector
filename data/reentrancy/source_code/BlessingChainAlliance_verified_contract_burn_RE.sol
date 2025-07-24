/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a burn rewards loyalty system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Accumulation**: Introduced `burnRewards[msg.sender] += _value / 100` that accumulates rewards across multiple burn transactions
 * 2. **External Call After State Update**: Added call to `loyaltyContract.onBurn()` after state modifications (violates CEI pattern)
 * 3. **State-Dependent External Call**: The external call only triggers when `burnRewards[msg.sender] > 0`, requiring prior state accumulation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn(100)` - accumulates 1 burnReward point, no external call yet
 * 2. **Transaction 2**: Attacker calls `burn(200)` - accumulates 2 more points (total 3), triggers external call
 * 3. **Reentrancy**: The malicious loyalty contract re-enters `burn()` during the external call
 * 4. **State Inconsistency**: The reentrancy occurs after `balanceOf` and `totalSupply` are updated but before the transaction completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires accumulated `burnRewards` state from previous transactions
 * - The external call only happens when `burnRewards[msg.sender] > 0`, not on first burn
 * - Attackers must build up rewards across multiple burns before the reentrancy vector becomes available
 * - The state accumulation creates a window of vulnerability that persists between transactions
 * 
 * **Exploitation Impact:**
 * - Attacker can drain tokens by re-entering burn while having inconsistent state
 * - Multiple burns can be executed with stale balance checks
 * - Total supply can become inconsistent with actual token balances
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Moved interface to top-level scope
interface ILoyaltyContract {
    function onBurn(address _who, uint256 _value);
}

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

    // Added: mapping for burnRewards
    mapping (address => uint256) public burnRewards;
    // Added: variable for loyaltyContract
    address public loyaltyContract;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add burn reward tracking for loyalty program
        burnRewards[msg.sender] += _value / 100;              // 1% burn rewards accumulate
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external loyalty contract about burn event
        if (loyaltyContract != address(0) && burnRewards[msg.sender] > 0) {
            // Use old-style call to the external contract instead of try/catch (which is unsupported in 0.4.8)
            ILoyaltyContract(loyaltyContract).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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