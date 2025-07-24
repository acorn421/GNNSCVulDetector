/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding State Persistence**: A new mapping `pendingOwnershipTransfers` tracks pending ownership transfers across transactions, creating persistent state that enables multi-transaction exploitation.
 * 
 * 2. **External Call Before State Update**: The function now makes an external call to `newOwner.call()` to notify the new owner BEFORE completing the ownership transfer. This violates the checks-effects-interactions pattern and creates a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `transferOwnership()` with a malicious contract address. The contract is marked as pending, external call is made, but if the call fails, the ownership transfer remains incomplete while the pending state persists.
 *    - **Transaction 2+**: The attacker can exploit the pending state by calling other contract functions that might check `pendingOwnershipTransfers` or by attempting the ownership transfer again while the contract is in an intermediate state.
 * 
 * 4. **Stateful Vulnerability**: The `pendingOwnershipTransfers` mapping creates persistent state between transactions. An attacker can manipulate this state across multiple transactions, potentially:
 *    - Causing the contract to be stuck in a pending state
 *    - Exploiting functions that rely on the pending state
 *    - Re-entering during the external call to manipulate contract state while ownership is transitioning
 * 
 * 5. **Realistic Attack Scenario**: The attacker deploys a malicious contract that:
 *    - In transaction 1: Causes the initial ownership transfer to fail, leaving it pending
 *    - In transaction 2: Calls other contract functions while the ownership is in limbo
 *    - In transaction 3: Completes or manipulates the ownership transfer
 * 
 * This vulnerability requires multiple transactions because the pending state must be established in one transaction and then exploited in subsequent transactions, making it a genuine multi-transaction, stateful reentrancy vulnerability.
 */
pragma solidity ^0.4.8;
contract Ownable {
  address public owner;
  

  function Ownable() {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    if (msg.sender != owner) {
      throw;
    }
    _;
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Track pending ownership transfers to enable multi-transaction exploitation
mapping(address => bool) public pendingOwnershipTransfers;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function transferOwnership(address newOwner) onlyOwner {
    if (newOwner != address(0)) {
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Mark this transfer as pending before external call
      pendingOwnershipTransfers[newOwner] = true;
      
      // External call to notify the new owner (vulnerable point)
      // This allows reentrancy while ownership transfer is in progress
      if (newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
        // Only complete the transfer if notification succeeded
        owner = newOwner;
        pendingOwnershipTransfers[newOwner] = false;
      } else {
        // If notification fails, leave the transfer pending
        // This creates a stateful vulnerability across multiple transactions
        // The pending state persists and can be exploited later
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
  }
  
  function kill() onlyOwner {
     selfdestruct(owner);
  }
}
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract GCSToken is Ownable{
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    function () {
        throw;
    }
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function GCSToken(
        ) {
        balanceOf[msg.sender] = 210000000000000000;              // Give the creator all initial tokens
        totalSupply = 210000000000000000;                        // Update total supply
        name = "Gamechain System";                                   // Set the name for display purposes
        symbol = "GCS";                              // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
        
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
}