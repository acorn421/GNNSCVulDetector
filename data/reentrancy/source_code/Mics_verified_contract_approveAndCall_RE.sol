/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Variables**: 
 *    - `pendingApprovals`: Tracks approval amounts during the approval process
 *    - `approvalActive`: Boolean flag indicating if an approval is currently being processed
 * 
 * 2. **State Modification Before External Call**: The function sets the approval state variables before making the external call to `receiveApproval`, creating a window for reentrancy.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: User calls `approveAndCall()` → sets `approvalActive[user][spender] = true` and `pendingApprovals[user][spender] = value`
 *    - **During External Call**: Malicious spender contract's `receiveApproval()` function can now call back into the token contract
 *    - **Transaction 2**: In the callback, the malicious contract can exploit the fact that `approvalActive` is still true and `pendingApprovals` contains the value
 *    - **Transaction 3+**: Additional exploitation transactions can leverage the persistent state that remains set until the original call completes
 * 
 * 4. **Vulnerability Requirements**:
 *    - **Stateful**: Uses persistent mappings that maintain state between transactions
 *    - **Multi-Transaction**: Requires the initial `approveAndCall` transaction to set state, then subsequent reentrancy calls to exploit it
 *    - **Realistic**: The state tracking appears legitimate (could be for preventing double-spending or tracking approval status)
 * 
 * 5. **Exploitation Scenario**:
 *    - Malicious spender implements `receiveApproval()` to call back into the token contract
 *    - During callback, it can check `approvalActive[user][attacker]` and `pendingApprovals[user][attacker]` to determine if it's in a vulnerable state
 *    - Can perform additional approvals or transfers while the original approval process is still "active"
 *    - The vulnerability persists across multiple function calls until the original `approveAndCall` completes
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability where the exploit requires multiple calls and depends on persistent state accumulated from previous transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract Mics {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function Mics(
        ) public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Mics";                                   // Set the name for display purposes
        symbol = "MICS";                               // Set the symbol for display purposes
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
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => mapping (address => uint256)) public pendingApprovals;
    mapping (address => mapping (address => bool)) public approvalActive;
    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track that approval process is starting
        approvalActive[msg.sender][_spender] = true;
        pendingApprovals[msg.sender][_spender] = _value;
        
        if (approve(_spender, _value)) {
            // External call before clearing approval state - vulnerable to reentrancy
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            
            // Clear approval state only after external call
            approvalActive[msg.sender][_spender] = false;
            delete pendingApprovals[msg.sender][_spender];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear state if approval failed
        approvalActive[msg.sender][_spender] = false;
        delete pendingApprovals[msg.sender][_spender];
        return false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}