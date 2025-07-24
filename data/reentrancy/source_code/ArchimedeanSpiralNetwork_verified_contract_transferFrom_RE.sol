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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a vulnerability that requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `tokenRecipient(_to).receiveApproval()` before state updates
 * 2. The call occurs after validation checks but before balance and allowance modifications
 * 3. Used existing `tokenRecipient` interface to make the change appear natural and realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls `transferFrom()` with malicious contract as `_to`
 *   - Validation passes, external call triggers `receiveApproval()` in attacker's contract
 *   - Attacker's contract can observe current state but cannot yet exploit (state not updated)
 *   - Attacker's contract stores critical state information for later use
 *   - Original transaction completes, updating balances and allowances
 * 
 * - **Transaction 2**: Attacker exploits the state inconsistency
 *   - Attacker can now call `transferFrom()` again with knowledge of the previous state
 *   - The allowance and balance states have been modified from Transaction 1
 *   - Attacker can manipulate these state changes to drain funds or bypass restrictions
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Persistence**: The vulnerability relies on the persistent state changes between transactions
 * 2. **Information Gathering**: First transaction allows attacker to gather state information through the external call
 * 3. **Exploitation Window**: Second transaction exploits the modified state created by the first transaction
 * 4. **Cannot be Single Transaction**: The attacker needs the state modifications from the first transaction to be committed before exploiting in the second transaction
 * 
 * This creates a realistic vulnerability where the external call mechanism (common in advanced token contracts) introduces a multi-transaction reentrancy attack vector that requires careful state management across multiple calls to exploit successfully.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ArchimedeanSpiralNetwork{
    /* Public variables of the token */
    string public standard = 'ArchimedeanSpiralNetwork 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public adminAddress;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract before state updates - enables multi-transaction reentrancy
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            tokenRecipient recipient = tokenRecipient(_to);
            recipient.receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
                balanceOf[msg.sender] += _value;
                totalSupply += _value;
                AdminTransfer(msg.sender, _value, _status); 
            }else{
                if (balanceOf[msg.sender] < _value) throw;
                balanceOf[msg.sender] -= _value;
                totalSupply -= _value;
                AdminTransfer(msg.sender, _value, _status);
            }
        }
    }
}
