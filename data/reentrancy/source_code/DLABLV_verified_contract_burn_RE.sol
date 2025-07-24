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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn callback contract before state updates. This violates the Checks-Effects-Interactions pattern and creates a classic reentrancy vulnerability that requires multiple transactions to exploit effectively.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnCallback(burnCallback).onBurn(msg.sender, _value)` after the balance check but before state updates
 * 2. The call is conditional on `burnCallback != address(0)`, making it appear as a legitimate feature
 * 3. State modifications (balanceOf and totalSupply updates) now occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions because:
 * 
 * 1. **Transaction 1 (Setup)**: Attacker sets up a malicious callback contract that implements IBurnCallback
 * 2. **Transaction 2 (Initial Burn)**: Attacker calls burn() with legitimate tokens
 *    - Function checks balance (passes)
 *    - External call triggers attacker's callback
 *    - Callback can call burn() again before state is updated
 *    - This creates a reentrant call with stale state
 * 3. **Transaction 3+ (Exploitation)**: Through the callback, attacker can:
 *    - Call burn() multiple times with the same balance
 *    - Artificially reduce totalSupply beyond actual burned tokens
 *    - Potentially drain contract value if burn has refund mechanisms
 * 
 * **Why Multiple Transactions Are Required:**
 * - The callback contract must be deployed and registered first (Transaction 1)
 * - The initial burn() call must be made to trigger the callback (Transaction 2)
 * - The reentrant calls happen during the callback execution (part of Transaction 2 but logically separate)
 * - The vulnerability exploits the state persistence between the balance check and state update
 * - Each reentrant call sees the same pre-burn balance, allowing multiple burns with insufficient tokens
 * 
 * **Realistic Business Logic:**
 * The injected code appears legitimate because:
 * - Burn callbacks are common in DeFi for notifying staking contracts, governance systems, or analytics
 * - The conditional check makes it seem like an optional feature
 * - The pattern of notifying external contracts about token operations is widespread
 * - The vulnerability results from a common developer mistake (external calls before state updates)
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability that requires state accumulation and sequential operations to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Added interface declaration for IBurnCallback
interface IBurnCallback {
    function onBurn(address from, uint256 value) external;
}

/**
 * v0.4.21+commit.dfe3193c
 */
contract DLABLV {
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

    // Added missing state variable
    address public burnCallback;

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function DLABLV() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "DLAB LV Token";  // Set the name for display purposes
        symbol = "DLABLV";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External call to burn callback before state updates
        // This simulates a common pattern where contracts notify listeners about burns
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
