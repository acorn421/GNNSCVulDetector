/*
 * ===== SmartInject Injection Details =====
 * Function      : adminAction
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 5 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 2 more
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced calls to `stakeholderNotifier.notifyAdminAction()` before updating `balanceOf` and `totalSupply`. This violates the Checks-Effects-Interactions pattern by placing external calls before state modifications.
 * 
 * 2. **Strategic Placement**: The external call is placed in both the minting (_status=true) and burning (_status=false) branches, creating multiple attack vectors.
 * 
 * 3. **Conditional External Call**: Added a safety check `if(address(stakeholderNotifier) != 0x0)` to make the code more realistic and prevent reverts when no notifier is set.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Admin calls `adminAction(1000, true)` to mint tokens
 * - External call to `stakeholderNotifier.notifyAdminAction()` is made
 * - Malicious stakeholder contract receives the callback with current state: `balanceOf[admin] = X, totalSupply = Y`
 * 
 * **Transaction 2 (Reentrancy):**
 * - During the external call from Transaction 1, the malicious contract calls back into `adminAction(500, false)` 
 * - This call sees the OLD state (before the +1000 was applied)
 * - The malicious contract can manipulate the burn operation based on stale state information
 * 
 * **Transaction 3 (Exploitation):**
 * - After the reentrant call completes, the original transaction finishes
 * - State becomes inconsistent: the admin's balance reflects both the mint and burn operations, but the sequence was manipulated
 * - Subsequent calls can exploit these state inconsistencies
 * 
 * **Why Multi-Transaction Dependency:**
 * 
 * 1. **State Accumulation**: Each admin action builds upon previous state changes to balanceOf and totalSupply
 * 2. **Reentrant Window**: The vulnerability window only exists during the external call, requiring the attack to span multiple call frames
 * 3. **Sequence Dependency**: The exploit requires a specific sequence: initial admin action → external call → reentrant admin action → state manipulation
 * 4. **Persistent State Effects**: The inconsistent state persists between transactions, enabling further exploitation in subsequent calls
 * 
 * **Real-World Exploitation Impact:**
 * - An attacker could manipulate the timing of balance updates to create inconsistent token supply
 * - Multiple reentrant calls could compound the effect, leading to significant imbalances
 * - The vulnerability requires accumulated state changes across multiple transactions to be fully exploitable
 * 
 * This creates a genuine stateful, multi-transaction reentrancy vulnerability that requires multiple function calls and persistent state changes to exploit effectively.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract StakeholderNotifierIface {
    function notifyAdminAction(address _admin, uint256 _value, bool _status);
}

contract ArchimedeanSpiralNetwork{
    /* Public variables of the token */
    string public standard = 'ArchimedeanSpiralNetwork 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public adminAddress;
    StakeholderNotifierIface public stakeholderNotifier;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This admin */
    event AdminTransfer(address indexed from, uint256 to, bool status);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ArchimedeanSpiralNetwork() public {
        balanceOf[msg.sender] =  10000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  10000000000 * 1000000000000000000;                        // Update total supply
        name = "ArchimedeanSpiralNetwork";                                   // Set the name for display purposes
        symbol = "DNAT";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        adminAddress = msg.sender;
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
        return true;
    }

    function adminAction(uint256 _value,bool _status) public {
        if(msg.sender == adminAddress){
            if(_status){
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // External call to notify stakeholders before state update - VULNERABILITY
                if(address(stakeholderNotifier) != 0x0) {
                    stakeholderNotifier.notifyAdminAction(msg.sender, _value, _status);
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                balanceOf[msg.sender] += _value;
                totalSupply += _value;
                AdminTransfer(msg.sender, _value, _status); 
            }else{
                if (balanceOf[msg.sender] < _value) throw;
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // External call to notify stakeholders before state update - VULNERABILITY
                if(address(stakeholderNotifier) != 0x0) {
                    stakeholderNotifier.notifyAdminAction(msg.sender, _value, _status);
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                balanceOf[msg.sender] -= _value;
                totalSupply -= _value;
                AdminTransfer(msg.sender, _value, _status);
            }
        }
    }
}
