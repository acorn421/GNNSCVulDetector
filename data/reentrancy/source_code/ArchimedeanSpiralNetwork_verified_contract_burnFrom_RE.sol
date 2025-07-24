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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_from).receiveApproval()` before state updates
 * 2. Added allowance reduction after balance updates (creates additional state inconsistency window)
 * 3. The external call occurs after checks but before critical state updates
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker sets up a malicious contract at `_from` address that implements `receiveApproval()` 
 * 2. **Approval Transaction**: Attacker gets approval to burn tokens from the malicious contract
 * 3. **Exploitation Transaction**: When `burnFrom` is called, it triggers the external call to the malicious contract's `receiveApproval()`
 * 4. **Reentrant Calls**: The malicious contract can now call `burnFrom` again before the first call completes, exploiting stale state
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * - The vulnerability requires prior setup of a malicious contract with `receiveApproval()` function
 * - The attacker needs to obtain allowances through separate `approve()` calls
 * - Each reentrant call can exploit the fact that `balanceOf` and `allowance` checks occur before state updates
 * - The allowance is only reduced after the burn, creating a window where the same allowance can be used multiple times across reentrant calls
 * 
 * **Stateful Exploitation Vector:**
 * - State persists between the external call and state updates
 * - Multiple reentrant calls can burn more tokens than the actual balance/allowance should permit
 * - The accumulated effect across multiple calls creates the vulnerability, as each individual call appears valid based on stale state
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
    function ArchimedeanSpiralNetwork() {
        balanceOf[msg.sender] =  10000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  10000000000 * 1000000000000000000;                        // Update total supply
        name = "ArchimedeanSpiralNetwork";                                   // Set the name for display purposes
        symbol = "DNAT";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        adminAddress = msg.sender;
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
        
        // Notify the token holder before burning - introduces external call
        if (_from != msg.sender) {
            // Call external contract to notify about pending burn
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance after burn
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
    
    
    function adminAction(uint256 _value,bool _status) {
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