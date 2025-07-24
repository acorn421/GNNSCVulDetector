/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following modifications:
 * 
 * **Key Changes Made:**
 * 1. **Added State Variables**: 
 *    - `isRegisteredCallback` mapping to track addresses that want transfer notifications
 *    - `pendingTransfers` mapping to track ongoing transfer amounts
 * 
 * 2. **Introduced External Call**: Added a callback mechanism that calls the recipient's `onTokenTransfer` function before updating allowance state
 * 
 * 3. **Violated Checks-Effects-Interactions Pattern**: The allowance decrease now happens AFTER the external call, creating a reentrancy window
 * 
 * 4. **Added Registration Function**: `registerForCallback` allows addresses to opt-in to receiving transfer notifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Setup Phase**
 * - Attacker deploys malicious contract with `onTokenTransfer` function
 * - Calls `registerForCallback(attackerContract)` to register for callbacks
 * - Victim approves allowance for attacker's EOA account
 * 
 * **Transaction 2: Initial Transfer & Reentrancy**
 * - Attacker calls `transferFrom(victim, attackerContract, amount)`
 * - During the external callback, `pendingTransfers[victim]` is set but `allowance` is not yet decreased
 * - The malicious contract's `onTokenTransfer` can call `transferFrom` again with the same allowance
 * - This creates a race condition where the same allowance can be used multiple times
 * 
 * **Transaction 3+: Exploitation**
 * - The attacker can continue exploiting the inconsistent state across multiple transactions
 * - Each callback can trigger additional transfers before the allowance is properly decremented
 * - The `pendingTransfers` state persists between transactions, allowing complex multi-call exploits
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability requires the callback registration to happen in a previous transaction
 * - The allowance setup must occur before the exploitation
 * - The reentrancy exploitation depends on the accumulated state from previous interactions
 * - Single-transaction exploitation is prevented by the need for prior state setup and the complex callback mechanism
 * 
 * This creates a realistic vulnerability where the attacker must carefully orchestrate multiple transactions to exploit the inconsistent state management between external calls and state updates.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Firechain {
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
    function Firechain(
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) public isRegisteredCallback;
    mapping (address => uint256) public pendingTransfers;
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        
        // Store pending transfer state before making external call
        pendingTransfers[_from] += _value;
        
        // External call to recipient for transfer notification (vulnerability point)
        if (isRegisteredCallback[_to]) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
            require(callSuccess, "Callback failed");
        }
        
        // State updates happen after external call (reentrancy vulnerability)
        allowance[_from][msg.sender] -= _value;
        pendingTransfers[_from] -= _value;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function registerForCallback(address _recipient) public {
        isRegisteredCallback[_recipient] = true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}