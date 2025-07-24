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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTED**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `TokenReceiver(_to).onTokenReceived(_from, _value, msg.sender)` before state updates
 * - The external call occurs after the allowance check but before the allowance is decremented
 * - Added contract existence check with `isContract(_to)` to make the callback realistic
 * - Positioned the external call to violate the Checks-Effects-Interactions pattern
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract with sufficient allowance
 * - Attacker deploys a malicious TokenReceiver contract as the recipient
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - Function checks allowance (passes)
 * - Function calls `maliciousContract.onTokenReceived()` BEFORE updating allowance
 * - During this callback, maliciousContract can call `transferFrom` again
 * - Since allowance hasn't been decremented yet, the second call also passes the allowance check
 * - This creates a reentrancy window where multiple transfers can occur
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The malicious contract can continue calling `transferFrom` in a loop
 * - Each call exploits the same allowance value since state hasn't been updated
 * - Attacker can drain much more than the originally approved amount
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Accumulation Dependency:**
 * - The vulnerability relies on allowance state persisting between transactions
 * - Attacker must first set up allowances in previous transactions
 * - The malicious recipient contract must be deployed and configured beforehand
 * 
 * **Reentrancy Window Exploitation:**
 * - First transaction establishes the allowance
 * - Second transaction triggers the reentrancy during the external call
 * - Additional transactions can continue the attack if the malicious contract is designed to maintain the attack state
 * 
 * **Cross-Transaction State Inconsistency:**
 * - The allowance state checked in transaction N enables exploitation in transaction N+1
 * - The vulnerability compounds as the attacker can use the same allowance multiple times
 * - Recovery requires separate transactions to restore proper state
 * 
 * **Realistic Attack Vector:**
 * This vulnerability mimics real-world token standards like ERC-777 that include recipient hooks, making it a realistic and dangerous injection that requires sophisticated multi-transaction coordination to exploit effectively.
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface TokenReceiver {
    function onTokenReceived(address _from, uint256 _value, address _operator) public;
}

contract XDToken {
    // Public variables of the token
    string public name = "XwcDice Token";
    string public symbol = "XDT";
    uint256 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply = 100*1000*1000*10**decimals;

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
    function XDToken() public {
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
     * Helper function to check whether address is a contract
     */
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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

        // INJECTED: External call to recipient notification before state update
        if (_to != address(0) && _to != _from && isContract(_to)) {
            // Notify recipient contract about incoming transfer
            TokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
