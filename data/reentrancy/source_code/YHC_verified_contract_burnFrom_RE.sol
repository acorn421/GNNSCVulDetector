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
 * 1. **External Call Injection**: Added an external call to `tokenRecipient(_from).receiveApproval()` before state updates, creating a reentrancy entry point.
 * 
 * 2. **Violation of CEI Pattern**: The external call now occurs after checks but before effects (state modifications), violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Conditional External Call**: The call only occurs when `_from != msg.sender`, making it more realistic as a notification mechanism.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract at address `attackerContract`
 * - Victim calls `approve(attackerContract, 1000)` to allow the attacker to burn tokens
 * - State: `allowance[victim][attackerContract] = 1000`, `balanceOf[victim] = 1000`
 * 
 * **Transaction 2 (Exploit):**
 * - Attacker calls `burnFrom(victim, 500)` from their malicious contract
 * - Function checks pass: `balanceOf[victim] >= 500` and `allowance[victim][attackerContract] >= 500`
 * - External call triggers: `tokenRecipient(victim).receiveApproval(attackerContract, 500, this, "burn")`
 * - **Critical**: If `victim` is a malicious contract, it can re-enter `burnFrom()` during this call
 * - During reentrancy, the victim's contract calls `burnFrom(victim, 500)` again
 * - **Second call still passes checks** because state hasn't been updated yet:
 *   - `balanceOf[victim]` is still 1000
 *   - `allowance[victim][attackerContract]` is still 1000
 * - Both calls complete their state updates, resulting in:
 *   - `balanceOf[victim] -= 500` (twice) = 0
 *   - `allowance[victim][attackerContract] -= 500` (twice) = 0
 *   - `totalSupply -= 500` (twice) = incorrect total supply
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The allowance must be set in a previous transaction using `approve()`, creating persistent state that enables the vulnerability.
 * 
 * 2. **Sequential Dependency**: The exploit requires:
 *    - Transaction 1: Set up allowance via `approve()`
 *    - Transaction 2: Execute `burnFrom()` with reentrancy
 * 
 * 3. **Accumulated State Exploitation**: The vulnerability leverages the fact that allowances accumulate over time and the function trusts the current state during the external call.
 * 
 * 4. **Contract Interaction Required**: The vulnerability requires the `_from` address to be a contract that can implement malicious reentrancy logic, which must be deployed in advance.
 * 
 * **Realistic Nature**: This vulnerability pattern is realistic because:
 * - Token burn notifications are legitimate functionality
 * - The `tokenRecipient` interface already exists in the contract
 * - The conditional check makes it seem like a reasonable optimization
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.19;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract YHC  {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 6;
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
    function YHC (
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
        
        // Notify the token holder about the burn operation (vulnerable external call)
        if (_from != msg.sender) {
            // Call to user-controlled contract before state updates
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}