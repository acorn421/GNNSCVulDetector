/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call After State Updates**: Introduced a callback mechanism `IBurnCallback(msg.sender).onBurn(msg.sender, _value)` that occurs AFTER the balance and totalSupply have been updated but BEFORE the function completes.
 * 
 * 2. **Contract Code Check**: Added `msg.sender.code.length > 0` check to determine if the caller is a contract, following realistic patterns for callback implementations.
 * 
 * 3. **Try-Catch Pattern**: Used try-catch to handle callback failures gracefully, maintaining backward compatibility with EOA accounts and non-callback contracts.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements IBurnCallback
 * - Attacker obtains some tokens through normal means
 * - The malicious contract's `onBurn` callback is designed to re-enter the burn function
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burn(amount)` from their malicious contract
 * - The burn function updates balanceOf[attacker] and totalSupply
 * - The callback `onBurn` is triggered AFTER state updates
 * - Inside the callback, the attacker can re-enter `burn()` again
 * - Since the callback occurs after state changes, subsequent re-entries see the updated state
 * 
 * **Transaction 3+ (State Accumulation):**
 * - The attacker can continue the reentrancy chain across multiple transactions
 * - Each transaction can build upon the state changes from previous transactions
 * - The persistent state modifications create opportunities for complex exploitation patterns
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The vulnerability leverages the fact that `balanceOf` and `totalSupply` changes persist between transactions, allowing attackers to build upon previous state modifications.
 * 
 * 2. **Callback Timing**: The external call occurs after state updates, meaning re-entrant calls see the modified state from the current transaction, but can also chain with previous transactions.
 * 
 * 3. **Accumulated Effects**: An attacker can orchestrate multiple burn transactions where each one:
 *    - Modifies the persistent state (balanceOf, totalSupply)
 *    - Triggers callbacks that can re-enter with the updated state
 *    - Chains with previous transactions to create complex attack patterns
 * 
 * 4. **Cross-Transaction Dependencies**: The vulnerability becomes more powerful when combined with other state-dependent operations across multiple transactions, such as:
 *    - Setting up allowances in one transaction
 *    - Burning tokens in another with reentrancy
 *    - Exploiting the accumulated state changes in subsequent transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires sophisticated multi-transaction exploitation strategies, making it suitable for security research and testing advanced detection tools.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Add IBurnCallback interface declaration to avoid unknown type error
interface IBurnCallback {
    function onBurn(address from, uint256 value) external;
}

contract DVNToken {
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
    function DVNToken(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external callback interface about burn event
        // This creates a reentrancy vulnerability after state changes
        if (isContract(msg.sender)) {
            // In Solidity 0.4.x, there's no try/catch or code property, so call directly
            // Swallow errors with address.call, maintaining vulnerability
            /* solium-disable-next-line security/no-low-level-calls */
            IBurnCallback(msg.sender).onBurn(msg.sender, _value);
            // Note: No error handling - callback failures will throw in 0.4.x
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
        Burn(_from, _value);
        return true;
    }
}
