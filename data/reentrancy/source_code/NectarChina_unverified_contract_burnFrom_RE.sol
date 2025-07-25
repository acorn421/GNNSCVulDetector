/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) after updating the balance but before updating the allowance and totalSupply. This creates a window for reentrancy where the attacker can exploit the inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_from` address using low-level call with `onTokenBurn` signature
 * 2. Moved the external call after `balanceOf[_from]` update but before `allowance` and `totalSupply` updates
 * 3. Added contract code length check to only call contracts (realistic optimization)
 * 4. Continued execution regardless of call result to maintain functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker contract gets approved allowance from victim
 * 2. **First Burn Transaction**: Attacker calls `burnFrom` on victim tokens:
 *    - `balanceOf[victim]` is reduced
 *    - External call triggers attacker's `onTokenBurn` callback
 *    - In callback, attacker can call `burnFrom` again or other functions
 *    - `allowance` and `totalSupply` not yet updated, creating inconsistent state
 * 3. **Reentrancy Exploitation**: During callback, attacker can:
 *    - Call `burnFrom` again with same allowance (since allowance not yet decremented)
 *    - Call other functions that depend on `totalSupply` being accurate
 *    - Extract more value due to inconsistent state between balance and allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance must be set up in a previous transaction (via `approve`)
 * - The vulnerability requires the external call to reenter during execution
 * - The stateful nature means the attacker needs to accumulate allowance over multiple transactions
 * - The inconsistent state (balance updated but allowance/totalSupply not) persists across the reentrant call stack
 * - Maximum exploitation requires orchestrating multiple burns across different transactions to fully drain tokens beyond the original allowance
 * 
 * This creates a realistic vulnerability where the attacker can burn more tokens than their allowance permits by exploiting the state inconsistency window created by the external call placement.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract NectarChina {
    // Public variables of the token
    string public name = "World Wisdom Union Asset";
    string public symbol = "WWUA";
    uint256 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply = 1300000000000000000000000000;

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
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Subtract from the targeted balance first
        balanceOf[_from] -= _value;
        
        // External call to notify the token holder about the burn - VULNERABILITY POINT
        // Note: In Solidity 0.4.x, 'code' member does not exist, so we use extcodesize assembly
        uint256 extcodesize;
        address addr = _from;
        assembly { extcodesize := extcodesize(addr) }
        if (extcodesize > 0) {
            /* solium-disable-next-line security/no-low-level-calls */
            _from.call(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value);
            // Continue execution regardless of call result
        }
        
        // State updates happen after external call - VULNERABILITY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(_from, _value);
        return true;
    }
}
