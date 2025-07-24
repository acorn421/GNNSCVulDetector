/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. **Added Stateful Tracking**: Introduced `pendingBurns` mapping to track burn amounts across transactions
 * 2. **External Call Before State Updates**: Added external call to `msg.sender.call()` with `onBurnNotification()` before critical state updates
 * 3. **Violated Checks-Effects-Interactions**: Moved state modifications (`balanceOf` and `totalSupply` updates) to occur AFTER the external call
 * 4. **Multi-Transaction State Window**: Created a window where `pendingBurns` is incremented but actual burns aren't completed
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Burn:**
 * - User calls `burn(100)` 
 * - `require(balanceOf[msg.sender] >= 100)` passes (e.g., balance = 200)
 * - `pendingBurns[msg.sender] += 100` (now pendingBurns = 100)
 * - External call to `msg.sender.onBurnNotification(100)` is made
 * - **Key Point**: If the external contract doesn't complete immediately or delays, the transaction ends here
 * 
 * **Transaction 2 - Reentrancy Attack:**
 * - The external contract (controlled by attacker) calls `burn(100)` again
 * - `require(balanceOf[msg.sender] >= 100)` still passes (balance still = 200, not yet decremented)
 * - `pendingBurns[msg.sender] += 100` (now pendingBurns = 200)
 * - Another external call is made, potentially creating more reentrancy
 * 
 * **Transaction 3 - State Completion:**
 * - Eventually, the original external calls complete
 * - `balanceOf[msg.sender] -= 100` executes multiple times
 * - `totalSupply -= 100` executes multiple times
 * - User burns more tokens than they should be able to
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The `pendingBurns` mapping accumulates across transactions, creating exploitable state
 * 2. **Asynchronous External Calls**: The external call might not complete in the same transaction, requiring subsequent transactions to exploit
 * 3. **Timing Window**: The vulnerability exploits the time window between the balance check and state updates across multiple transactions
 * 4. **Cannot be Atomic**: The exploit requires the external contract to make additional calls, which cannot happen atomically in a single transaction due to the external call dependency
 * 
 * This creates a realistic multi-transaction reentrancy vulnerability where an attacker needs to coordinate multiple function calls and rely on accumulated state changes to exploit the flaw.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract JadeCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Added declaration for pendingBurns to fix undeclared identifier error
    mapping(address => uint256) public pendingBurns;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function JadeCoin(
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        // Add pending burn amount to track multi-transaction state
        pendingBurns[msg.sender] += _value;
        // External call to user's contract for burn notification BEFORE state updates
        // This creates the reentrancy vulnerability window
        if (isContract(msg.sender)) {
            // In 0.4.16, there is no .code so we use extcodesize via inline assembly
            uint256 retval;
            assembly { retval := extcodesize(msg.sender) }
            if (retval > 0) {
                msg.sender.call(
                    abi.encodeWithSignature("onBurnNotification(uint256)", _value)
                );
                // Continue even if external call fails (ignore returned value)
            }
        }
        // State updates happen AFTER external call - creates reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Clear pending burn only after successful completion
        pendingBurns[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Helper function to determine if an address is a contract
     */
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
