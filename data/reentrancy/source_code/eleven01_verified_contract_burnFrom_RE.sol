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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTED**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `tokenRecipient(_from).receiveApproval()` before state updates
 * - The external call is positioned after input validation but before state modifications
 * - Used try-catch to make the external call appear legitimate and non-blocking
 * - The call only happens when `_from != msg.sender` to make it seem like a reasonable notification feature
 * 
 * **2. Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker sets up initial allowance through `approve()` or gets approval from a victim
 * - Attacker deploys a malicious contract that implements `tokenRecipient` interface
 * - The malicious contract's `receiveApproval` function will be the reentrant callback
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burnFrom()` targeting the malicious contract's address as `_from`
 * - The function passes initial checks (balance and allowance validation)
 * - External call is made to the malicious contract's `receiveApproval` function
 * - **CRITICAL**: At this point, checks have passed but state updates haven't occurred yet
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - Inside the malicious contract's `receiveApproval` callback, the attacker can:
 *   - Call `burnFrom()` again before the original state updates complete
 *   - Since the original state hasn't been updated yet, the same allowance can be used multiple times
 *   - Each reentrant call passes the same validation checks using stale state
 *   - This allows burning more tokens than the allowance should permit
 * 
 * **3. Why Multi-Transaction Nature is Essential:**
 * 
 * **State Accumulation Requirement:**
 * - The vulnerability requires building up allowances across multiple transactions first
 * - Each exploitation cycle needs separate transaction contexts to bypass gas limits
 * - The reentrant calls create a chain of nested transactions that each exploit stale state
 * 
 * **Cross-Transaction State Persistence:**
 * - The allowance state persists between transactions, making repeated exploitation possible
 * - Each successful burn reduces the actual balance but not the allowance being checked
 * - Attackers can prepare multiple malicious contracts across different transactions
 * 
 * **Time-Based Exploitation:**
 * - Real-world exploitation would involve multiple transactions over time
 * - Each transaction exploits the window between validation and state updates
 * - The cumulative effect across multiple transactions amplifies the damage
 * 
 * **4. Realistic Attack Vector:**
 * An attacker could:
 * 1. **Setup Phase**: Deploy malicious contracts implementing `tokenRecipient`
 * 2. **Allowance Phase**: Obtain or manipulate allowances to target addresses
 * 3. **Exploitation Phase**: Execute multiple `burnFrom` calls where each reentrant callback exploits stale state
 * 4. **Amplification Phase**: Repeat across multiple transactions to maximize token drainage
 * 
 * This creates a realistic vulnerability that requires sophisticated multi-transaction coordination to exploit effectively, making it a valuable test case for security analysis tools.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract eleven01 {
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
    function eleven01(
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
        Burn(msg.sender, _value);
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
        
        // Notify the token holder about the burn through external call
        if (_from != msg.sender) {
            // Call external contract to notify about burn - VULNERABILITY: External call before state updates
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn_notification");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
