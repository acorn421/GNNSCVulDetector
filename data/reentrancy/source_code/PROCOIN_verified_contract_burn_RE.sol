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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: 
 *    - `burnCallbacks` mapping to track user-registered callback contracts
 *    - `pendingBurns` mapping to track burns in progress
 * 
 * 2. **Introduced External Call Before State Updates**:
 *    - Added callback mechanism that calls external contract before balance/totalSupply updates
 *    - Uses existing `tokenRecipient` interface from the contract for realistic integration
 * 
 * 3. **Created Reentrancy Window**:
 *    - External call happens after `pendingBurns` increment but before balance/totalSupply updates
 *    - State changes moved to occur after external call
 * 
 * 4. **Added Helper Function**:
 *    - `setBurnCallback()` allows users to register callback contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Setup Phase**
 * - Attacker deploys malicious contract implementing `tokenRecipient`
 * - Attacker calls `setBurnCallback(maliciousContract)` to register callback
 * - Attacker accumulates tokens in their balance
 * 
 * **Transaction 2: Exploitation Phase**
 * - Attacker calls `burn(amount)` with their tokens
 * - Function increments `pendingBurns[attacker]` 
 * - External call to malicious contract is made BEFORE balance/totalSupply updates
 * - Malicious contract re-enters `burn()` function during callback
 * - On re-entry, `require(balanceOf[msg.sender] >= _value)` still passes (balance not yet reduced)
 * - `pendingBurns` increases again, but balance reduction hasn't happened yet
 * - This creates inconsistent state where more tokens can be burned than the user actually has
 * 
 * **Transaction 3: State Accumulation**
 * - Multiple re-entries can accumulate `pendingBurns` beyond actual balance
 * - Each re-entry creates deeper inconsistency between pending burns and actual balance
 * - Eventually totalSupply can be reduced below actual circulating supply
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **Setup Dependency**: Attacker must first register callback contract (Transaction 1)
 * 2. **State Accumulation**: The vulnerability relies on accumulating inconsistent state across multiple re-entries
 * 3. **Persistent State**: `pendingBurns` and `burnCallbacks` persist between transactions, enabling the attack
 * 4. **Sequential Exploitation**: Cannot be exploited in a single atomic transaction - requires the callback registration step followed by the burn call
 * 
 * **Realistic Vulnerability Pattern:**
 * This follows real-world patterns where protocols add notification mechanisms or external integrations without proper reentrancy protection, creating stateful vulnerabilities that require multiple transactions to exploit effectively.
 */
pragma solidity >=0.4.22 <0.6.0;

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}

contract PROCOIN {
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
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string memory tokenName,
        string memory tokenSymbol
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
        require(_to != address(0x0));
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        emit Approval(msg.sender, _spender, _value);
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
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
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
mapping (address => address) public burnCallbacks;
    mapping (address => uint256) public pendingBurns;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Add to pending burns before any state changes
        pendingBurns[msg.sender] += _value;
        
        // Notify external callback if registered (VULNERABILITY: external call before state update)
        if (burnCallbacks[msg.sender] != address(0)) {
            tokenRecipient(burnCallbacks[msg.sender]).receiveApproval(msg.sender, _value, address(this), "");
        }
        
        // State updates happen after external call - creates reentrancy window
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burns only after all state updates
        pendingBurns[msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function setBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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