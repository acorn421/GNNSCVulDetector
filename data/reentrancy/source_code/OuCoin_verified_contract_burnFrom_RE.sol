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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder before state updates are finalized. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_from).receiveApproval()` before state updates
 * 2. Used existing `tokenRecipient` interface to make the call realistic
 * 3. Deliberately omitted the allowance decrement that should occur after burning
 * 4. Placed the external call after checks but before effects (classic reentrancy pattern)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burnFrom` with legitimate parameters
 * 2. **During Transaction 1**: External call triggers attacker's malicious contract
 * 3. **Reentrant Call**: Malicious contract calls `burnFrom` again before original state changes
 * 4. **State Accumulation**: Multiple burns occur but allowance is never decremented
 * 5. **Transaction 2+**: Process repeats, allowing attacker to burn more tokens than allowance permits
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent state between the allowance check and its update
 * - Each reentrant call creates a new transaction context where the same allowance can be reused
 * - The attacker needs to accumulate state changes across multiple calls to exceed their actual allowance
 * - Single-transaction exploitation is prevented by the initial balance/allowance checks
 * 
 * **Attack Vector:**
 * An attacker can deploy a malicious contract that implements `receiveApproval` to make reentrant calls to `burnFrom`, effectively burning more tokens than their allowance permits by exploiting the time window between the external call and state updates.
 */
pragma solidity ^0.4.14;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract OuCoin {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public constant name = "OuCoin";
    string public constant symbol = "IOU";
    uint8 public constant decimals = 3;
    uint256 public constant initialSupply = 10000000;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function OuCoin () {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require (balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
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
        require (_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                 // Check if the sender has enough
        require (balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (_value <= allowance[_from][msg.sender]);    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder before burning (external call vulnerability)
        if (_from != address(0) && isContract(_from)) {
            // External call before state updates - creates reentrancy window
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // NOTE: allowance NOT decremented here, creating additional vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }

    // Helper function to detect contracts (since .code.length and try/catch are not available in 0.4.14)
    function isContract(address _addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
