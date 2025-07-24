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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Tracking**: Introduced `pendingBurns` mapping to track ongoing burn operations across transactions, creating state that persists between calls.
 * 
 * 2. **External Call Before State Updates**: Added a callback mechanism that calls external contracts BEFORE updating balances and totalSupply, violating the checks-effects-interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Attacker calls `burn()` with enabled notifications, triggering the external call
 *    - **During Callback**: The external contract can reenter `burn()` before the first call's state updates complete
 *    - **Transaction 2+**: Subsequent reentrant calls can exploit the inconsistent state where `pendingBurns` is updated but `balanceOf` is not yet decremented
 * 
 * 4. **Stateful Vulnerability Requirements**:
 *    - Requires prior transaction to enable burn notifications via `burnNotificationEnabled[msg.sender] = true`
 *    - Requires setting a callback contract address via `burnCallbacks[msg.sender] = attackerContract`
 *    - The vulnerability accumulates effect through the persistent `pendingBurns` state across multiple transactions
 * 
 * 5. **Realistic Integration**: The callback mechanism mimics common DeFi patterns where token burns trigger notifications to other contracts (liquidity pools, governance systems, etc.).
 * 
 * **Multi-Transaction Exploitation Sequence**:
 * 1. **Setup Transaction**: Attacker enables burn notifications and sets callback contract
 * 2. **Initial Burn**: Attacker calls burn(), external call is made before state updates
 * 3. **Reentrant Calls**: During callback, attacker can call burn() again, exploiting the window where `pendingBurns` is incremented but `balanceOf` not yet decremented
 * 4. **State Accumulation**: Multiple reentrant calls can burn more tokens than the attacker actually holds by exploiting the delayed state updates
 * 
 * This creates a genuine multi-transaction reentrancy where the vulnerability requires state setup across transactions and exploits the persistent state inconsistencies.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TAToken {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
    
    address public owner;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // ===================== Added for vulnerability ==================
    mapping(address => uint256) public pendingBurns;
    mapping(address => bool) public burnNotificationEnabled;
    mapping(address => address) public burnCallbacks;
    // ===============================================================

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }
    
    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TAToken() public {
        totalSupply = 150000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 70000000 * 10 ** uint256(decimals);                // Give the creator all initial tokens
        name = "Three and the chain";                                   // Set the name for display purposes
        symbol = "TA";                               // Set the symbol for display purposes
        owner = msg.sender;
    }
    
    /**
     * transferOwnership
     */
    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
    
    /**
     * Increase Owner token
     */
    function increaseSupply(uint _value) onlyOwner returns (bool)  {
        //totalSupply = safeAdd(totalSupply, value);
        balanceOf[owner] += _value;
        return true;
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
        // Subtract from the _spender
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Additional state variables needed (would be added to contract):
    // mapping(address => uint256) public pendingBurns;
    // mapping(address => bool) public burnNotificationEnabled;
    // mapping(address => address) public burnCallbacks;

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Add to pending burns for multi-transaction tracking
        pendingBurns[msg.sender] += _value;
        
        // External call BEFORE state finalization - introduces reentrancy window
        if (burnNotificationEnabled[msg.sender] && burnCallbacks[msg.sender] != address(0)) {
            // Call external contract - this can reenter before state is finalized
            tokenRecipient(burnCallbacks[msg.sender]).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // State updates happen AFTER external call - vulnerable to reentrancy
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Only clear pending burns after successful completion
        if (pendingBurns[msg.sender] >= _value) {
            pendingBurns[msg.sender] -= _value;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
