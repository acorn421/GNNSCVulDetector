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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient's onTokenReceived function before updating the allowance state. This creates a critical vulnerability that requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` before the allowance deduction
 * 2. The call attempts to invoke `onTokenReceived(address,address,uint256)` on the recipient contract
 * 3. The allowance state update occurs AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `approve()` to set allowance for malicious contract
 * 2. **Transaction 2**: Attacker calls `transferFrom()` which triggers the external call to malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` function is called while allowance is still at original value
 * 4. **Reentrancy**: The malicious contract recursively calls `transferFrom()` again, exploiting the fact that allowance hasn't been decremented yet
 * 5. **State Accumulation**: Multiple recursive calls can drain more tokens than the original allowance permitted
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires initial allowance setup via `approve()` (Transaction 1)
 * - The actual exploitation happens during `transferFrom()` (Transaction 2+)
 * - The attacker needs to deploy a malicious contract with `onTokenReceived()` function beforehand
 * - The exploit relies on the persistent state of the allowance mapping between transactions
 * - Each recursive call within the reentrancy leverages the unchanged allowance state from the initial transaction
 * 
 * **State Persistence:**
 * - The allowance mapping persists between transactions
 * - The vulnerability window exists because allowance is checked but not immediately decremented
 * - Multiple calls can exploit the same allowance value before it's finally updated
 * 
 * This creates a realistic vulnerability that mimics real-world token transfer notification patterns while introducing a critical security flaw that requires multiple transactions and state accumulation to exploit.
 */
pragma solidity ^0.4.13;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract MINEX {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
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
    constructor() public {
        balanceOf[msg.sender] = 2999029096950000;              // Give the creator all initial tokens
        totalSupply = 2999029096950000;                        // Update total supply
        name = 'MINEX';                                   // Set the name for display purposes
        symbol = 'MINEX';                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
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
        
        // External call to recipient before state update - introduces reentrancy window
        if (isContract(_to)) {
            // Call recipient's onTokenReceived function if it exists
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if address is a contract (for <0.8.0)
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
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
        public returns (bool success) {
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
