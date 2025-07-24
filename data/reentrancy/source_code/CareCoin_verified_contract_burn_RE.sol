/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. **Added State Variables**: 
 *    - `burnNotifier`: Address of external contract to notify about burns
 *    - `pendingBurns`: Mapping to track pending burn amounts per user
 *    - `burnSequence`: Counter for burn operations
 * 
 * 2. **External Call Before State Updates**: Added `IBurnNotifier(burnNotifier).onBurnInitiated()` call before balance modifications, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Pending Burn Tracking**: Added `pendingBurns[msg.sender] += _value` before external call and `pendingBurns[msg.sender] -= _value` after state updates.
 * 
 * 4. **Burn Sequence Counter**: Added `burnSequence++` to track burn operations across transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Burn):**
 * - User calls `burn(100)` with sufficient balance (e.g., 1000 tokens)
 * - `pendingBurns[user] += 100` (now 100)
 * - `burnSequence++` (now 1)
 * - External call to `burnNotifier.onBurnInitiated(user, 100, 1)`
 * - The external contract can now see that user has 100 pending burns
 * - Balance and totalSupply are updated: `balanceOf[user] -= 100` (now 900)
 * - `pendingBurns[user] -= 100` (back to 0)
 * 
 * **Transaction 2 (Reentrancy Exploit):**
 * - Malicious `burnNotifier` contract calls `burn(100)` again on user's behalf
 * - Since `pendingBurns[user]` was reset to 0 in Transaction 1, the check passes
 * - Balance check passes (user still has 900 tokens)
 * - `pendingBurns[user] += 100` (now 100 again)
 * - External call triggers again, potentially calling `burn()` in Transaction 3
 * - State updates proceed, reducing balance to 800
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The `pendingBurns` mapping persists between transactions, allowing the attacker to track and exploit burn operations across multiple calls.
 * 
 * 2. **Cross-Transaction Reentrancy**: The external call in Transaction 1 can trigger a separate Transaction 2 where the attacker re-enters the `burn()` function while the original transaction's state is still being processed.
 * 
 * 3. **Accumulated State Exploitation**: The vulnerability exploits the fact that state updates happen after external calls, and the `pendingBurns` tracking can be manipulated across multiple transactions to bypass balance checks.
 * 
 * 4. **Sequence Dependency**: The `burnSequence` counter creates a dependency chain where later transactions can reference and potentially exploit earlier transaction states.
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to exploit, as the attacker must first trigger the external call, then use that call to initiate additional burn operations while the original transaction's state changes are still being processed.
 */
pragma solidity ^0.4.13;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotifier {
    function onBurnInitiated(address from, uint256 value, uint256 sequence) external;
}

contract CareCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    address public burnNotifier;
    mapping(address => uint256) public pendingBurns;
    uint256 public burnSequence;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Record pending burn for multi-transaction tracking
        pendingBurns[msg.sender] += _value;
        burnSequence++;
        // External call to burn notifier BEFORE state updates (reentrancy vulnerability)
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onBurnInitiated(msg.sender, _value, burnSequence);
        }
        // State updates happen after external call - vulnerable to reentrancy
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
     * Destroy tokens from other ccount
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
