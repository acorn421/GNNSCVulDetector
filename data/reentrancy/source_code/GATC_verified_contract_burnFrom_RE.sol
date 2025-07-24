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
 * 1. **Added External Call Between Checks and Effects**: Introduced a low-level `.call()` to notify the token holder (`_from`) about the burn operation via an `onTokensBurned(address,uint256)` callback.
 * 
 * 2. **Positioned Call Before State Updates**: The external call occurs after the allowance verification but before the critical state updates (balance reduction, allowance decrement, totalSupply update).
 * 
 * 3. **Conditional Execution**: The callback only executes when `_from != msg.sender`, making it appear as a reasonable feature for third-party burn notifications.
 * 
 * 4. **Realistic Justification**: The callback mechanism allows token holders to implement custom burn logic, similar to the existing `approveAndCall` pattern.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements the `onTokensBurned` callback
 * - Token holder approves the malicious contract to spend tokens via `approve()`
 * - The allowance is now stored in state: `allowance[holder][malicious_contract] = X`
 * 
 * **Transaction 2 (Initial Exploitation):**
 * - Malicious contract calls `burnFrom(holder_address, amount)`
 * - Function passes allowance check: `amount <= allowance[holder][malicious_contract]`
 * - External call triggers: `holder_address.call(onTokensBurned, malicious_contract, amount)`
 * - **Critical Reentrancy Window**: If `holder_address` is the malicious contract itself, it can re-enter
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - During the callback, the malicious contract calls `burnFrom` again
 * - The allowance hasn't been decremented yet, so the same allowance can be used multiple times
 * - Each re-entrant call burns more tokens than the allowance should permit
 * - State variables are manipulated multiple times before the original call completes
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The allowance must be set up in a prior transaction through `approve()`
 * 2. **Persistent State Dependency**: The vulnerability exploits the fact that `allowance[_from][msg.sender]` persists between transactions and is checked before being updated
 * 3. **Callback Mechanism**: The external call creates a window where the contract state is inconsistent (allowance checked but not yet decremented)
 * 4. **Multi-Call Exploitation**: The attacker can make multiple calls within the reentrancy window, each using the same allowance value before it gets updated
 * 
 * **Realistic Attack Scenario:**
 * An attacker could drain more tokens than authorized by:
 * 1. Getting approval for a specific amount
 * 2. Calling `burnFrom` which triggers the callback
 * 3. Re-entering through the callback to call `burnFrom` multiple times
 * 4. Each call uses the same allowance value, effectively multiplying the burn amount
 * 
 * This creates a stateful vulnerability where the allowance system's integrity depends on proper state management across multiple transaction boundaries.
 */
pragma solidity ^0.4.16;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract GATC {
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
    function GATC(
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
        
        // Notify the token holder about the burn operation before state updates
        // This allows for custom burn logic implementation
        if (_from != msg.sender) {
            bytes4 sig = bytes4(keccak256("onTokensBurned(address,uint256)"));
            require(_from.call(sig, msg.sender, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}