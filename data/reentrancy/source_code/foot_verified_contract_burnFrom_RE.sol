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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY ANALYSIS:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `tokenRecipient(_from).receiveApproval()` after validation checks but BEFORE state updates
 * - The external call notifies the token holder about the burn operation, which is a realistic feature
 * - Used existing `tokenRecipient` interface from the contract for authentic integration
 * - Added contract existence check `_from.code.length > 0` to make it realistic
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker creates a malicious contract that implements `tokenRecipient` interface
 * - Attacker gets approved allowance from the malicious contract to burn tokens
 * - The malicious contract holds tokens and has approved the attacker to burn them
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `burnFrom(maliciousContract, amount)`
 * - Function validates checks (balance and allowance are sufficient)
 * - External call triggers `maliciousContract.receiveApproval()` callback
 * - **CRITICAL**: At this point, state variables (balanceOf, allowance, totalSupply) are NOT yet updated
 * - Inside the callback, malicious contract can:
 *   - Call `burnFrom()` again with same parameters (reentrancy)
 *   - Call `approve()` to restore allowance
 *   - Call `transfer()` to move tokens before they're burned
 *   - Manipulate other contract functions that depend on current balances
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - Subsequent transactions can exploit the inconsistent state created by the reentrancy
 * - The malicious contract can continue calling functions that benefit from the temporary state inconsistency
 * 
 * **3. Why Multi-Transaction Requirement:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability relies on the allowance mechanism that persists between transactions
 * - Attacker must first obtain approval (Transaction 1) before exploiting (Transaction 2+)
 * - The malicious contract must be deployed and configured before exploitation
 * 
 * **Accumulated State Effects:**
 * - Each reentrant call during the callback can modify contract state
 * - These state changes accumulate and persist, affecting subsequent transactions
 * - The attacker can exploit the window where external calls are made but state updates haven't completed
 * 
 * **Realistic Exploitation Pattern:**
 * - Real-world exploitation would involve setting up the malicious contract first
 * - Then executing the burnFrom call that triggers the vulnerable callback
 * - Finally, leveraging the compromised state in follow-up transactions
 * 
 * **4. Vulnerability Impact:**
 * - Double-spending of burn operations
 * - Manipulation of totalSupply calculations
 * - Potential theft of tokens during the reentrancy window
 * - Violation of token accounting invariants across multiple transactions
 * 
 * This creates a realistic, stateful vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract foot {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 0;
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
    function TokenERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = 10000 ;  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "腳腳幣";                                   // Set the name for display purposes
        symbol = "腳腳幣";                               // Set the symbol for display purposes
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
        
        // Notify the token holder about the burn operation (VULNERABILITY: External call before state updates)
        if (extcodesize(_from) > 0) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }

    // Necessary for extcodesize in Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }
}
