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
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism that calls `tokenRecipient(_from).receiveApproval()` after the initial checks but before any state modifications.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call occurs after checks but before effects (state updates), creating a reentrancy window.
 * 
 * 3. **Conditional Callback**: Added a realistic condition `if (_from != msg.sender)` to make the callback seem legitimate (notifying the token holder when someone else burns their tokens).
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker creates a malicious contract implementing `tokenRecipient` interface
 * - Attacker gets approval to burn tokens from the malicious contract's address
 * - The malicious contract has tokens and has given the attacker allowance
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Attacker calls `burnFrom(maliciousContract, amount)`
 * - The function passes initial checks (balance and allowance are sufficient)
 * - External call is made to `maliciousContract.receiveApproval()`
 * - **Critical**: State variables (balanceOf, allowance, totalSupply) are NOT yet updated
 * 
 * **Transaction 3+ (Reentrancy Chain):**
 * - Inside `receiveApproval()`, the malicious contract calls `burnFrom()` again
 * - Since state hasn't been updated yet, the same tokens can be burned multiple times
 * - Each reentrant call sees the original, unchanged state
 * - This continues until gas limits are reached or the attack succeeds
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Persistence**: The vulnerability relies on the persistent state (balanceOf, allowance) remaining unchanged between the external call and state updates across multiple transaction contexts.
 * 
 * 2. **Accumulated Exploitation**: Each reentrant call exploits the same unchanged state, allowing the attacker to burn more tokens than they should be able to, or burn tokens multiple times.
 * 
 * 3. **Allowance Draining**: The attacker can drain the allowance multiple times before it gets decremented, potentially burning more tokens than authorized.
 * 
 * 4. **Cross-Transaction State Dependency**: The vulnerability depends on the state set up in previous transactions (approvals, balances) while exploiting the gap between external calls and state updates.
 * 
 * **Real-World Impact:**
 * - Tokens can be burned multiple times using the same allowance
 * - Total supply can be reduced more than intended
 * - The token holder loses more tokens than they approved for burning
 * - The attacker can effectively "multiply" their burning power through reentrancy
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract TianqibaoTokenERC20 {
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
        
        // Notify the token holder about the burn operation via callback
        // This external call happens before state updates - creating reentrancy vulnerability
        if (_from != msg.sender) {
            tokenRecipient notifyContract = tokenRecipient(_from);
            notifyContract.receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
