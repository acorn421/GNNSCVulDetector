/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder before state updates. The vulnerability exploits the fact that the external call occurs before critical state variables (balanceOf, allowance, totalSupply) are updated, creating a window for reentrancy attacks across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `tokenRecipient(_from).receiveApproval()` before state updates
 * 2. The call is made to the `_from` address if it's a contract, simulating a burn notification mechanism
 * 3. State variables are updated AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker gets approved allowance from victim contract
 * - Victim contract implements `receiveApproval()` function controlled by attacker
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burnFrom(victimContract, amount)`
 * - Function passes initial checks (balance and allowance validation)
 * - External call to `victimContract.receiveApproval()` is made
 * - During this call, the victim contract's state shows:
 *   - `balanceOf[victimContract]` still has original value
 *   - `allowance[victimContract][attacker]` still has original value
 *   - These haven't been decremented yet
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - From within `receiveApproval()`, victim contract can call back to `burnFrom()` again
 * - Since state hasn't been updated yet, the same allowance can be used multiple times
 * - Or victim contract can call other token functions that depend on the unchanged state
 * - This creates opportunities for double-spending allowances or manipulating burn amounts
 * 
 * **Why Multi-Transaction Nature is Required:**
 * 1. **State Persistence**: The vulnerability depends on the persistent state of allowances and balances that accumulate over multiple function calls
 * 2. **Allowance Exploitation**: Attacker needs to first obtain legitimate allowance approval (separate transaction)
 * 3. **Reentrancy Chain**: The external call creates opportunities for callback functions that can trigger additional state-dependent operations
 * 4. **Accumulated Impact**: Multiple reentrant calls can compound the effect, burning more tokens than should be allowed by the original allowance
 * 
 * The vulnerability cannot be exploited in a single atomic transaction because it requires the setup of allowances and the exploitation of the time window between external calls and state updates across multiple function invocations.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 150000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 70000000 * 10 ** uint256(decimals);                // Give the creator all initial tokens
        name = "Three and the chain";                                   // Set the name for display purposes
        symbol = "TA";                               // Set the symbol for display purposes
        owner = msg.sender;
    }
    
    /**
     * transferOwnership
     */
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
    
    /**
     * Increase Owner token
     */
    function increaseSupply(uint _value) onlyOwner public returns (bool)  {
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
        
        // Notify the token holder about the burn before updating state
        uint codeLength;
        assembly { codeLength := extcodesize(_from) }
        if (_from != address(0) && codeLength > 0) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
