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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added state variables**: `burnCallback` mapping to store user-defined callback contracts, and `burnPendingRewards` to track accumulated rewards across multiple burns
 * 
 * 2. **External call after state changes**: Added callback to `IBurnCallback(burnCallback[msg.sender]).onTokensBurned()` AFTER balance and totalSupply updates, violating the Checks-Effects-Interactions pattern
 * 
 * 3. **Reward accumulation mechanism**: Introduced `burnPendingRewards` that accumulates across multiple burn operations, creating persistent state dependencies
 * 
 * 4. **Multi-transaction exploitation path**:
 *    - **Transaction 1**: Attacker calls `setBurnCallback()` to register malicious callback contract
 *    - **Transaction 2**: Attacker calls `burn()` with legitimate tokens
 *    - **During callback**: Malicious contract calls `burn()` again, but balance check uses stale state
 *    - **Transaction 3**: Attacker calls `claimBurnRewards()` to mint reward tokens
 * 
 * 5. **Stateful dependency**: The vulnerability requires:
 *    - Callback registration (persistent state)
 *    - Accumulated burn rewards (persistent state)
 *    - Multiple burn operations to amplify the effect
 * 
 * The vulnerability is NOT exploitable in a single transaction because:
 * - The callback contract must be pre-registered
 * - Rewards accumulate across multiple burns
 * - The external call enables reentrancy but requires the callback setup state
 * - Maximum damage requires multiple burn operations to build up rewards
 * 
 * **Exploitation Scenario**:
 * 1. Attacker registers malicious callback contract
 * 2. Attacker burns tokens → callback triggered → callback calls burn() again
 * 3. Due to reentrancy, second burn() sees original balance before first burn completed
 * 4. Attacker can burn more tokens than owned and accumulate inflated rewards
 * 5. Attacker claims accumulated rewards, minting new tokens
 * 
 * This creates a realistic burn reward system that's vulnerable to multi-transaction reentrancy attacks.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Fixed incorrect interface keyword 'iinterface' to 'interface'
interface IBurnCallback {
    function onTokensBurned(address from, uint256 value) external;
}

contract BICKCOIN {
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
    mapping (address => address) public burnCallback;
    mapping (address => uint256) public burnPendingRewards;
    
    function burn(uint256 _value) public returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Calculate burn reward (1% of burned tokens)
        uint256 reward = _value / 100;
        if (reward > 0) {
            burnPendingRewards[msg.sender] += reward;
        }
        
        emit Burn(msg.sender, _value);
        
        // Notify burn callback contract after state changes
        if (burnCallback[msg.sender] != address(0)) {
            IBurnCallback(burnCallback[msg.sender]).onTokensBurned(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function setBurnCallback(address _callback) public {
        burnCallback[msg.sender] = _callback;
    }
    
    function claimBurnRewards() public {
        require(burnPendingRewards[msg.sender] > 0);
        uint256 reward = burnPendingRewards[msg.sender];
        burnPendingRewards[msg.sender] = 0;
        balanceOf[msg.sender] += reward;
        totalSupply += reward;
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
