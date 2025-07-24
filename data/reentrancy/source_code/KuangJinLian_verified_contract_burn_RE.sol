/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 
 * 1. **Pending Burns Tracking**: Added `pendingBurns` mapping to track burn operations across transactions
 * 2. **External Call Before State Updates**: Added external call to `burnRecipient` contract before updating balances
 * 3. **State Updates After External Call**: Moved balance and supply updates to occur after the external call
 * 4. **Multi-Transaction State Dependency**: The vulnerability requires multiple transactions to exploit effectively
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1**: Attacker calls burn() with legitimate value, triggering external call to malicious contract
 * - **Transaction 2**: During the external call, the malicious contract re-enters burn() function
 * - **Exploitation**: The pendingBurns state persists between transactions, and the balance checks can be bypassed through accumulated state manipulation across multiple calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent `pendingBurns` state that accumulates across calls
 * - Multiple transactions are needed to build up sufficient pending burn state to exploit the balance validation
 * - The external call creates a window where state is inconsistent across multiple transaction boundaries
 * - Single-transaction exploitation is prevented by the balance check, but multi-transaction exploitation can manipulate the accumulated pending state
 * 
 * **Required Additional State Variables:**
 * ```solidity
 * mapping (address => uint256) public pendingBurns;
 * address public burnRecipient;
 * ```
 * 
 * This creates a realistic vulnerability where a token burning system with external notifications becomes exploitable through reentrancy across multiple transactions.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract KuangJinLian{
    /* Public variables of the token */
    string public standard = 'JinKuangLian 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Added state for reentrancy vulnerability
    mapping (address => uint256) public pendingBurns; // <-- Added
    address public burnRecipient; // <-- Added

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function KuangJinLian() public {
        balanceOf[msg.sender] =  1200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1200000000 * 1000000000000000000;                        // Update total supply
        name = "KuangJinLian";                                   // Set the name for display purposes
        symbol = "KJL";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
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
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending burn tracking for multi-transaction burn process
        pendingBurns[msg.sender] += _value;
        
        // External call to notify burn recipient contract before state updates
        if (burnRecipient != address(0)) {
            tokenRecipient recipient = tokenRecipient(burnRecipient);
            recipient.receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burn only after successful completion
        pendingBurns[msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
