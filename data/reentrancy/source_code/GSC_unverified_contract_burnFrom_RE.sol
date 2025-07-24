/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * 1. **Added External Call Before State Updates**: Introduced a call to `_from.call()` that invokes an `onBurnNotification` function on the `_from` address before any state modifications occur.
 * 
 * 2. **Notification Pattern**: Added a realistic "notification" mechanism that could appear in production code, where the contract being burned from is notified about the operation.
 * 
 * 3. **Vulnerable Call Placement**: The external call is placed after the checks (require statements) but before the effects (state modifications), creating a classic reentrancy vulnerability.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract at address `MaliciousContract`
 * - Attacker calls `approve(attackerEOA, largeAmount)` from `MaliciousContract` to grant allowance
 * - Attacker seeds `MaliciousContract` with some tokens
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker's EOA calls `burnFrom(MaliciousContract, amount)`
 * - During the external call to `MaliciousContract.onBurnNotification()`, the malicious contract:
 *   - Calls `approve(attackerEOA, newLargeAmount)` to increase allowance
 *   - Calls `transfer()` to move tokens to attacker's addresses
 *   - Potentially calls `burnFrom()` again recursively with different parameters
 * - The original `burnFrom` completes, but the state is now inconsistent
 * 
 * **Transaction 3+ - Exploitation Continuation:**
 * - Attacker can exploit the manipulated state from previous transactions
 * - Use the inflated allowances or manipulated balances from the reentrancy
 * - Chain multiple `burnFrom` calls to drain funds systematically
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability leverages allowance and balance state that must be set up in prior transactions through `approve()` and `transfer()` calls.
 * 
 * 2. **Persistent State Manipulation**: The reentrancy modifies persistent state variables (allowance, balanceOf) that remain changed between transactions, enabling exploitation in subsequent calls.
 * 
 * 3. **Complex Exploitation Pattern**: The full exploit requires:
 *    - Initial setup of allowances and balances
 *    - Reentrancy to manipulate state mid-transaction
 *    - Follow-up transactions to realize the gains from the state manipulation
 * 
 * 4. **Cross-Transaction Dependencies**: Each transaction builds upon the state changes from previous transactions, making it impossible to exploit in a single atomic transaction.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to fully exploit, while maintaining the function's original purpose and appearing as a reasonable enhancement (burn notification) that could exist in production code.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract GSC {
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
    function GSC(
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the _from address about the burn operation before state changes
        if (_from != msg.sender) {
            // Call external contract to notify about burn operation
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onBurnNotification(address,uint256)", msg.sender, _value));
            // Continue even if notification fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}