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
 * The vulnerability is introduced through a multi-transaction reentrancy attack pattern:
 * 
 * **Specific Changes Made:**
 * 1. Added `pendingBurns` mapping to track burn operations in progress
 * 2. Added a require statement to prevent concurrent burns from the same address
 * 3. Introduced an external call to `burnObserver.onBurnInitiated()` after the balance check but before state updates
 * 4. Added state flag management around the external call
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability can be exploited across multiple transactions as follows:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `IBurnObserver`
 * - Attacker calls some admin function to set their contract as the `burnObserver`
 * - Attacker accumulates tokens in their EOA account
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `burn()` from their EOA with their full balance
 * - The function checks balance (passes), sets `pendingBurns[attacker] = true`
 * - External call is made to attacker's malicious observer contract
 * - In the callback, the malicious contract calls `burn()` again from a different address (controlled by attacker)
 * - The second call succeeds because `pendingBurns` only blocks the same address, not all addresses
 * - This allows the attacker to burn more tokens than the total supply through coordinated reentrancy
 * 
 * **Transaction 3+ (Exploitation):**
 * - The attacker can repeat this pattern with multiple addresses
 * - Each address can initiate a burn that triggers callbacks to other addresses
 * - The vulnerable window between balance check and state update allows multiple burns to see the same pre-burn state
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence**: The `pendingBurns` mapping persists between transactions, creating a stateful vulnerability
 * 2. **Setup Dependency**: The attack requires setting up the malicious observer contract first
 * 3. **Coordination**: The exploit requires coordinating multiple addresses and their burn operations
 * 4. **Accumulated Effect**: The vulnerability compounds across multiple burn operations, with each transaction building on the state modifications of previous ones
 * 
 * This creates a realistic vulnerability where the reentrancy guard is insufficient, and the external call placement violates the Checks-Effects-Interactions pattern in a way that requires multiple transactions to fully exploit.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnObserver {
    function onBurnInitiated(address _from, uint256 _value) public;
}

contract PrettyGirl {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // New variable for burn observer
    address public burnObserver;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function PrettyGirl(
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
    mapping (address => bool) public pendingBurns;

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        require(!pendingBurns[msg.sender], "Burn already in progress");

        pendingBurns[msg.sender] = true;            // Mark burn as pending

        // External call to notify burn observer before state changes
        if (burnObserver != address(0)) {
            IBurnObserver(burnObserver).onBurnInitiated(msg.sender, _value);
        }

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        pendingBurns[msg.sender] = false;           // Clear pending flag
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
