/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic reentrancy vulnerability where:
 * 
 * **Specific Changes Made:**
 * 1. Added a conditional external call to `_to.call()` if the recipient is a contract
 * 2. The external call happens BEFORE the allowance is updated (`allowance[_from][msg.sender] -= _value`)
 * 3. This violates the Checks-Effects-Interactions pattern by performing interactions before effects
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * 2. **During Transaction 1**: The external call to `onTokenReceived()` is made before allowance is updated
 * 3. **Reentrant Call**: The malicious contract's `onTokenReceived()` function calls `transferFrom()` again
 * 4. **Transaction 2** (nested): Second `transferFrom()` call sees the original allowance (not yet decremented)
 * 5. **State Accumulation**: Each nested call can transfer the full allowance amount before any allowance updates occur
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger a reentrant call back to `transferFrom()`
 * - The nested call (Transaction 2) depends on the state from Transaction 1 (original allowance not yet updated)
 * - Multiple calls are needed to drain more tokens than the original allowance permits
 * - The exploit accumulates state changes across nested transactions where allowance checks pass but updates are delayed
 * 
 * **Exploitation Scenario:**
 * 1. Attacker gets approval for 100 tokens
 * 2. Calls `transferFrom(owner, maliciousContract, 100)`
 * 3. Before allowance is updated, `maliciousContract.onTokenReceived()` is called
 * 4. Malicious contract immediately calls `transferFrom(owner, attacker, 100)` again
 * 5. Second call sees original allowance (100) and succeeds
 * 6. Process can repeat multiple times before allowance updates propagate
 * 7. Result: Attacker drains more than 100 tokens using 100 token allowance
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple function calls and state persistence between transactions to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ELYTE {
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
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract (added external call before state update)
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // External call to recipient contract before updating allowance
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue even if call fails to maintain functionality
        }
        
        // Update allowance AFTER external call (vulnerability: state update after external call)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
