/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the spender before updating the allowance state. This creates a vulnerable window where the spender can re-enter the contract during the notification callback while the allowance is still at its previous value.
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code existence at the spender address
 * 2. Added an external call to `tokenRecipient(_spender).receiveApproval()` before state updates
 * 3. Used try-catch to handle potential failures gracefully
 * 4. Moved the allowance state update to occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: User calls approve() for a malicious contract with amount X
 * 2. **Transaction 2**: During the receiveApproval callback, the malicious contract:
 *    - Calls transferFrom() to spend the OLD allowance value
 *    - Or calls approve() again to manipulate allowance state
 *    - Can also call other functions that depend on allowance state
 * 3. **State Persistence**: The allowance mapping persists between transactions, enabling the attack
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy their malicious contract and get it approved
 * - The vulnerability exploits the timing between the external call and state update
 * - The attacker's contract needs to be set up to handle the receiveApproval callback
 * - The exploitation relies on the persistent allowance state that accumulates across calls
 * - The reentrancy opportunity only exists during the callback window across transaction boundaries
 * 
 * This creates a realistic vulnerability where the notification mechanism (a common pattern in token contracts) introduces a reentrancy vector that can be exploited through multiple coordinated transactions.
 */
pragma solidity ^0.4.18;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract WWNCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    constructor(
    ) public {
        totalSupply = 250000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "WWN Coin";                                   // Set the name for display purposes
        symbol = "WWN";                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }


    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if spender implements approval notification interface
        if (_spender != address(0)) { // Dummy check, selector removed for compatibility
            tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
        }
        // Update allowance state after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
}
