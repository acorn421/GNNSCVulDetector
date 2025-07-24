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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call `TokenReceiver(_to).onTokenReceived(_from, msg.sender, _value)` after the internal `_transfer()` call
 * - The external call is conditional based on whether `_to` is a contract (`_to.code.length > 0`)
 * - This creates a callback mechanism that notifies the recipient contract after token transfer
 * - The external call occurs AFTER critical state changes (allowance decrement and balance updates) but BEFORE function completion
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract as spender with sufficient allowance
 * - Attacker deploys a malicious contract that implements `onTokenReceived()` callback
 * - The malicious contract maintains internal state tracking previous calls
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Legitimate user calls `transferFrom()` to transfer tokens to the malicious contract
 * - The function executes normally: checks allowance, decrements allowance, transfers tokens
 * - At the end, the malicious contract's `onTokenReceived()` callback is triggered
 * - The callback records the transfer details and sets up state for future exploitation
 * 
 * **Transaction 3 (Exploitation):**
 * - The malicious contract calls `transferFrom()` again using the same allowance
 * - Due to the persistent state changes from Transaction 2, the malicious contract can:
 *   - Re-enter the function during the callback phase
 *   - Exploit the fact that allowance was already decremented but callback state persists
 *   - Potentially drain tokens by leveraging the callback mechanism across multiple transactions
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability relies on `allowance[_from][msg.sender]` state that persists between transactions
 * - Each transaction modifies this persistent state, creating opportunities for exploitation
 * - The callback mechanism creates a window where external contracts can observe and react to state changes
 * 
 * **Multi-Call Exploitation Pattern:**
 * - Single transaction exploitation is prevented by the allowance check at the beginning
 * - However, across multiple transactions, an attacker can:
 *   - Build up state information through callbacks
 *   - Exploit the timing between state updates and callback execution
 *   - Use the persistent allowance state to perform unauthorized transfers
 * 
 * **Cross-Transaction State Manipulation:**
 * - The malicious contract can track cumulative transfers across multiple calls
 * - Each callback provides information about the current state that can be exploited in subsequent transactions
 * - The attacker can coordinate multiple `transferFrom` calls to maximize the exploitation window
 * 
 * **4. Technical Exploitation Flow:**
 * 
 * ```solidity
 * // Attacker's malicious contract
 * contract MaliciousReceiver {
 *     mapping(address => uint256) public cumulativeReceived;
 *     
 *     function onTokenReceived(address _from, address _spender, uint256 _value) external {
 *         // Record state across transactions
 *         cumulativeReceived[_from] += _value;
 *         
 *         // In subsequent transactions, exploit the callback mechanism
 *         if(cumulativeReceived[_from] >= THRESHOLD) {
 *             // Trigger additional transferFrom calls
 *             // Exploit the state persistence across multiple transactions
 *             IntelligentTradingTechnologies(msg.sender).transferFrom(_from, address(this), EXPLOIT_AMOUNT);
 *         }
 *     }
 * }
 * ```
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that requires multiple function calls and persistent state changes to be fully exploitable, making it suitable for advanced security research and analysis.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract IntelligentTradingTechnologies {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
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
    function IntelligentTradingTechnologies(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract - VULNERABILITY INJECTION
        uint256 size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            // External call after state changes - creates reentrancy window
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
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
        public returns (bool success) {
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
