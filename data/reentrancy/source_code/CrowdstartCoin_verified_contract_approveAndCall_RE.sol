/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variable**: Introduced `mapping(address => mapping(address => uint256)) public pendingApprovals` to track pending approval operations between transactions.
 * 
 * 2. **State Update Before External Call**: Added `pendingApprovals[msg.sender][_spender] = _value` before the external call to create vulnerable state.
 * 
 * 3. **External Call Position**: Maintained the external call `spender.receiveApproval()` in the middle of the state management logic.
 * 
 * 4. **State Cleanup After External Call**: Added `pendingApprovals[msg.sender][_spender] = 0` AFTER the external call, creating the reentrancy window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - User calls `approveAndCall(maliciousContract, 1000, data)`
 * - `pendingApprovals[user][maliciousContract] = 1000` is set
 * - `approve()` sets `allowance[user][maliciousContract] = 1000`
 * - External call to `maliciousContract.receiveApproval()` is made
 * 
 * **During External Call (Reentrancy):**
 * - Malicious contract can re-enter `approveAndCall` or call `transferFrom`
 * - The `pendingApprovals` state persists and shows 1000 tokens pending
 * - Attacker can exploit this inconsistent state across multiple calls
 * 
 * **Transaction 2+ (Exploitation):**
 * - Attacker can call `transferFrom` using the approved allowance
 * - The `pendingApprovals` mapping still shows pending amounts from previous transactions
 * - Attacker can potentially drain tokens by exploiting the accumulated state
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the `pendingApprovals` mapping persisting state between transactions, creating exploitable conditions in subsequent calls.
 * 
 * 2. **Cross-Function Exploitation**: The attacker needs to use `transferFrom` in separate transactions to actually drain the tokens, making it impossible to exploit in a single atomic transaction.
 * 
 * 3. **Stateful Inconsistency**: The vulnerability depends on the inconsistent state between `pendingApprovals` and actual `allowance` mappings across multiple transaction boundaries.
 * 
 * 4. **Callback-Based Attack**: The external call creates a callback opportunity that can be exploited across multiple transactions through the persistent state variables.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to fully exploit, making it suitable for advanced security analysis and testing frameworks.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract CrowdstartCoin {
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

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function CrowdstartCoin(
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
        // Prevent transfer to 0x0 address.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Add this state variable to track pending approvals (add to contract state)
    mapping(address => mapping(address => uint256)) public pendingApprovals;
    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending approval before external call - creates stateful vulnerability
        pendingApprovals[msg.sender][_spender] = _value;
        
        if (approve(_spender, _value)) {
            // External call BEFORE clearing pending state - reentrancy vector
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            
            // Clear pending approval AFTER external call - too late!
            pendingApprovals[msg.sender][_spender] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        }
    }
}