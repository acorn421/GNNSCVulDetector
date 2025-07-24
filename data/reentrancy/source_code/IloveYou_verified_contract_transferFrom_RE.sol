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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability exploits the fact that allowances and balances persist between transactions, requiring multiple coordinated calls to exploit:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract and gets approval to spend tokens from victim accounts through normal approval mechanisms.
 * 
 * 2. **Transaction 2 (Initial Transfer)**: Attacker calls transferFrom() with their malicious contract as the recipient (_to). During the external call to onTokenReceived(), the malicious contract can:
 *    - Read the current state (balances, allowances)
 *    - Record information about pending transfers
 *    - BUT cannot immediately exploit because the state hasn't been updated yet
 * 
 * 3. **Transaction 3+ (Stateful Exploitation)**: In subsequent transactions, the attacker can:
 *    - Use the information gathered from previous calls to optimize their attack
 *    - Leverage the fact that allowances from previous transactions are still available
 *    - Chain multiple transferFrom calls where each call's external callback can trigger additional transfers using remaining allowances
 *    - Exploit the accumulated state where balances have been partially updated across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **State Persistence**: The vulnerability relies on allowances and balances persisting between transactions, allowing the attacker to build up exploitable state over multiple calls
 * - **Information Gathering**: The first transaction allows the attacker to discover available allowances and balances that can be exploited in subsequent transactions
 * - **Allowance Accumulation**: Multiple users may have granted allowances over time, and the attacker needs multiple transactions to systematically exploit each allowance through the reentrancy vector
 * - **Complex State Dependencies**: The exploit becomes more effective as the attacker accumulates knowledge about the contract's state across multiple interactions
 * 
 * The vulnerability is realistic because adding recipient notifications is a common pattern in modern token contracts, but the placement before state updates creates the classic reentrancy condition combined with stateful exploitation opportunities.
 */
pragma solidity ^0.4.6;
contract tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract IloveYou {
    /* Public variables of the Jack Currency*/
    string public standard = 'Donny 1.0';
    string public name = 'DonnyIloveMandy';
    string public symbol = 'DONLOVE';
    uint8 public decimals = 8;
    uint256 public totalSupply = 10000000000000000;

    /* Creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* Generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to me */
    function IloveYou() public {
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                 // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens on my behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        if ((_value != 0) && (allowance[msg.sender][_spender] != 0)) revert();
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerable: External call before state updates - enables stateful reentrancy
        // Check if _to is a contract by checking code size via assembly for pre-0.5.0
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // Call recipient contract to notify of incoming transfer
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue even if call fails to maintain backwards compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                              // Subtract from the sender
        balanceOf[_to] += _value;                                // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    /* Burn Dony by User */
    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                         // Subtract from the sender
        totalSupply -= _value;                                   // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

}
