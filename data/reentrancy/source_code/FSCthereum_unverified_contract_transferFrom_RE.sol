/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Reordered Operations**: Moved the allowance decrement (`allowance[_from][msg.sender] -= _value;`) to occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Added External Call**: Introduced a code check and assembly call to the recipient address (`_to`) before updating the allowance state. This simulates a token notification callback mechanism.
 * 
 * 3. **State Update Vulnerability**: The allowance is now decremented after the external call, creating a reentrancy window where the original allowance value is still available.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker gets approval for 100 tokens from victim
 * - Attacker deploys malicious contract as recipient
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 100)`
 * - During execution:
 *   1. Allowance check passes (100 <= 100)
 *   2. `_transfer()` moves 100 tokens to malicious contract
 *   3. External call to malicious contract triggers
 *   4. **Inside callback**: Malicious contract calls `transferFrom(victim, attacker, 100)` again
 *   5. **Second call sees same allowance** (still 100, not decremented yet)
 *   6. Second transfer succeeds, moving another 100 tokens
 *   7. Both calls finally decrement allowance by 100 each
 * 
 * **Result**: Attacker transfers 200 tokens with only 100 allowance.
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The allowance state persists between the nested calls within the same transaction, but the vulnerability requires the state to be "stale" during the reentrancy window.
 * 
 * 2. **Callback Dependency**: The external call creates a dependency where the malicious contract must respond to the callback, effectively creating a multi-step process even within a single transaction.
 * 
 * 3. **Accumulated State Abuse**: The vulnerability exploits the fact that state changes accumulate across multiple calls, with the allowance check happening before all state updates are complete.
 * 
 * This vulnerability is realistic because token notification callbacks are common in modern token standards (ERC-777, ERC-1155), and the ordering of state updates vs external calls is a frequent source of reentrancy vulnerabilities in production code.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract FSCthereum {
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

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
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
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        _transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to recipient before allowance update
        // This simulates a token notification callback pattern
        if (isContract(_to)) {
            // Call to potentially malicious contract
            assembly {
                let success := call(gas, _to, 0, 0, 0, 0, 0)
            }
        }
        
        allowance[_from][msg.sender] -= _value;  // State update AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
