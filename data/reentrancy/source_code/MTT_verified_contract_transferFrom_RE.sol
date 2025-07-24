/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Finalization**: Introduced a recipient notification mechanism that calls `onTokenReceived` on the recipient contract if it has code. This external call occurs after the allowance is decremented but before the actual token transfer is completed.
 * 
 * 2. **Positioned Call in Vulnerable Window**: The external call is placed at a critical point where the allowance has been partially updated but the full transaction state hasn't been finalized, creating a reentrancy window.
 * 
 * 3. **Maintained Original Functionality**: The core transferFrom logic remains intact - allowance checking, decrementation, and token transfer still occur as expected.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract with a large allowance (e.g., 1000 tokens)
 * - Legitimate user also approves the same malicious contract with some allowance
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 100)` 
 * - Function decrements allowance: `allowance[victim][attacker] -= 100`
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - During this callback, the malicious contract calls `transferFrom(victim, attacker, 100)` again
 * - The second call sees the already-decremented allowance but can still execute because `_transfer` hasn't completed
 * - This creates a race condition where multiple transfers can occur before the first transaction fully completes
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The malicious contract can continue making recursive calls during the callback
 * - Each call further decrements the allowance but the actual balance transfers may not be properly synchronized
 * - The attacker can drain more tokens than the original allowance permitted
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires building up allowances across multiple approve/transferFrom calls to create sufficient "ammunition" for the attack.
 * 
 * 2. **Callback Dependency**: The external call (`onTokenReceived`) only triggers if the recipient is a contract, requiring the attacker to first deploy a malicious contract in a separate transaction.
 * 
 * 3. **Allowance Manipulation**: The attack relies on the interplay between allowance decrements and balance transfers across multiple nested calls, where each call depends on the state changes from previous calls.
 * 
 * 4. **Reentrancy Chain**: The vulnerability creates a chain of reentrant calls where each subsequent call exploits the intermediate state left by the previous call, requiring multiple transaction contexts to fully exploit.
 * 
 * The vulnerability is realistic because it mimics token standards like ERC-777 that include recipient notification mechanisms, and the reentrancy occurs due to the classic "checks-effects-interactions" pattern violation where external calls happen before all state changes are finalized.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * v0.4.21+commit.dfe3193c
 */
contract MTT {
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
    constructor() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "AK47 Test";  // Set the name for display purposes
        symbol = "AK47Test";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract (vulnerable external call)
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call before final state updates - creates reentrancy window
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback result
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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