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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to `tokenRecipient(_from).receiveApproval()` before the state modifications occur, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Conditional External Call**: The external call only happens when `_from != msg.sender`, making it realistic for scenarios where someone is burning tokens on behalf of another account.
 * 
 * 3. **State Snapshot Storage**: Added variables to store the initial state (`oldBalance`, `oldAllowance`) which could be used for validation but creates additional attack surface.
 * 
 * 4. **Reused Existing Interface**: Leveraged the existing `tokenRecipient` interface already present in the contract, making the modification appear natural and realistic.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract implementing `tokenRecipient` interface
 * - Attacker approves the malicious contract to spend tokens
 * - The malicious contract's `receiveApproval` function is designed to call back into `burnFrom`
 * 
 * **Transaction 2 - Initial Burn:**
 * - Attacker calls `burnFrom(maliciousContract, amount)` 
 * - The function performs initial checks (balance >= amount, allowance >= amount)
 * - Before state updates, it calls `maliciousContract.receiveApproval()`
 * - The malicious contract's `receiveApproval` function immediately calls `burnFrom` again
 * 
 * **Transaction 3+ - Reentrancy Exploitation:**
 * - During the reentrant call, the checks still pass because state hasn't been updated yet
 * - The malicious contract can burn more tokens than originally allowed
 * - Each reentrant call can trigger further calls, creating a chain
 * - State accumulates across multiple nested calls, allowing over-burning
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * 
 * 1. **State Persistence**: The vulnerability exploits the fact that `balanceOf` and `allowance` mappings persist between transactions, allowing accumulated exploitation.
 * 
 * 2. **Allowance Accumulation**: An attacker can set up allowances across multiple transactions, then exploit them all at once through reentrancy.
 * 
 * 3. **Gas Limitations**: A single transaction cannot exploit this indefinitely due to gas limits, but multiple transactions can accumulate the exploit effect.
 * 
 * 4. **Cross-Transaction State Dependencies**: The exploit becomes more effective when the attacker can prepare state in earlier transactions (approvals, balances) and then exploit them in later transactions through reentrancy.
 * 
 * **Realistic Attack Vector:**
 * This vulnerability could realistically appear in production code where developers want to notify token holders about burn operations, but incorrectly implement the notification before state updates, creating a multi-transaction reentrancy vulnerability that persists across the contract's lifetime.
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract CBCK {
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
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function CBCK(
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
        
        // Store initial state for burn callback
        uint256 oldBalance = balanceOf[_from];
        uint256 oldAllowance = allowance[_from][msg.sender];
        
        // Notify the token owner about the burn operation before state updates
        // This external call creates a reentrancy window
        if (_from != msg.sender) {
            // Call to potentially malicious contract before state changes
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}