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
 * 1. **Added State Variable**: Introduced `mapping(address => address) public burnCallbacks;` to store user-controlled callback addresses that persist between transactions.
 * 
 * 2. **Added Helper Function**: Created `setBurnCallback(address _callback)` to allow users to register their callback contracts in a separate transaction.
 * 
 * 3. **Introduced External Call**: Added an external call to the user-controlled callback contract after the balance check but before state updates, violating the Checks-Effects-Interactions (CEI) pattern.
 * 
 * 4. **Preserved Function Logic**: Maintained all original functionality while creating the vulnerability.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker calls `setBurnCallback(maliciousContract)` to register their malicious contract
 * - This sets up the persistent state needed for the attack
 * 
 * **Transaction 2+ (Exploitation)**:
 * - Attacker calls `burn(amount)` with their token balance
 * - The function checks `balanceOf[attacker] >= amount` (passes)
 * - External call is made to attacker's callback contract
 * - **Reentrancy occurs**: Callback contract calls `burn()` again
 * - Second call passes the balance check (balance hasn't been updated yet)
 * - This can be repeated multiple times within the callback
 * - Eventually, all calls complete and balances are updated
 * - **Result**: Attacker burned more tokens than they actually owned
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Setup Phase**: The callback address must be registered in a separate transaction before exploitation
 * 2. **Persistent State Dependency**: The vulnerability relies on the `burnCallbacks` mapping persisting between transactions
 * 3. **Accumulated Effect**: Multiple reentrant calls accumulate their effects, allowing the attacker to burn more tokens than their actual balance across the sequence of calls
 * 4. **Cannot be Exploited in Single Transaction**: Without the pre-registered callback, the vulnerability cannot be triggered
 * 
 * **Realistic Nature**: Token burning callbacks are common in DeFi protocols for notifications, hooks, and integration purposes, making this a realistic vulnerability pattern that could appear in production code.
 */
pragma solidity ^0.4.18;

interface tokenRecipient {
  function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

contract OST {
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
    function OST(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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

    /*******************
     * Extra functions *
     *******************/

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => address) public burnCallbacks;
    
    function setBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Call external callback before state updates (CEI pattern violation)
        if (burnCallbacks[msg.sender] != address(0)) {
            // External call to user-controlled contract before state changes
            (bool callSuccess,) = burnCallbacks[msg.sender].call(
                abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value)
            );
            require(callSuccess, "Callback failed");
        }
        
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}