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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 
 * 1. **State Variables**: Added `burnCallbacks` mapping to track registered callback contracts and `pendingBurns` to track burns in progress
 * 2. **External Call Before State Updates**: Added callback mechanism that makes external call to user-controlled contract BEFORE updating balances
 * 3. **Multi-Transaction Setup**: Added `registerBurnCallback` function that allows users to register callback contracts in a separate transaction
 * 4. **Persistent State Tracking**: `pendingBurns` tracks accumulated burn amounts across transactions
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `registerBurnCallback()` to register malicious contract
 * 2. **Transaction 2+**: Attacker calls `burn()` which triggers callback to malicious contract
 * 3. **During Callback**: Malicious contract can re-enter `burn()` or call other functions while `pendingBurns` is inflated but `balanceOf` hasn't been updated yet
 * 4. **State Inconsistency**: The gap between external call and state updates creates exploitable windows across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - Setup phase (registering callback) must happen in separate transaction
 * - `pendingBurns` state accumulates across calls, creating exploitable conditions
 * - Attacker needs to build up `pendingBurns` state over multiple transactions to maximize exploitation
 * - The vulnerability depends on the persistent state relationship between `pendingBurns`, `balanceOf`, and registered callbacks
 * 
 * **Realistic Exploitation Scenarios:**
 * - Attacker can manipulate `pendingBurns` to appear to have more tokens burning than they actually own
 * - Re-entrance during callback can exploit the window where `pendingBurns` is high but `balanceOf` unchanged
 * - Multiple burn calls can accumulate `pendingBurns` state to create arithmetic overflow conditions
 * - Cross-function attacks using inflated `pendingBurns` state in other contract functions
 */
pragma solidity ^0.4.16;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract CECToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function CECToken(
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
     * Remove `_value` tokens from the system irreversibly
     * @param _value the amount of money to burn
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => address) public burnCallbacks;
    mapping(address => uint256) public pendingBurns;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Add to pending burns before any state changes
        pendingBurns[msg.sender] += _value;
        
        // If user has registered a callback, notify them before state updates
        if (burnCallbacks[msg.sender] != address(0)) {
            // External call before state changes - creates reentrancy opportunity
            (bool callSuccess,) = burnCallbacks[msg.sender].call(
                abi.encodeWithSignature("onBurnNotification(address,uint256)", msg.sender, _value)
            );
            // Continue execution regardless of callback success
        }
        
        // State updates happen after external call
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burn only after successful state update
        pendingBurns[msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Function to register burn callback - enables multi-transaction setup
    function registerBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    /**
     * Destroy tokens from other account
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
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