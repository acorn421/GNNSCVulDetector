/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Moving state update after external call**: The critical `allowance[_from][msg.sender] -= _value;` line is moved AFTER the external call, creating a classic reentrancy vulnerability.
 * 
 * 2. **Adding external callback mechanism**: Introduces a callback to the recipient contract via `ITokenReceiver(_to).onTokenReceived()` which creates the reentrancy entry point.
 * 
 * 3. **Stateful exploitation across multiple transactions**: 
 *    - **Transaction 1**: Attacker calls transferFrom with allowance X. The transfer executes but allowance isn't decremented yet due to the callback.
 *    - **Callback**: Recipient contract re-enters transferFrom, still seeing the original allowance X (not decremented).
 *    - **Transaction 2**: Second transferFrom call succeeds again with same allowance, effectively double-spending.
 *    - **State accumulation**: Multiple transactions can drain more tokens than originally allowed.
 * 
 * 4. **Multi-transaction dependency**: The vulnerability requires:
 *    - Initial allowance setup (separate transaction)
 *    - First transferFrom call that triggers callback
 *    - Reentrant calls during callback that exploit unchanged allowance state
 *    - Accumulated effect over multiple calls to exceed original allowance
 * 
 * The vulnerability is realistic because:
 * - Token notification patterns are common in DeFi
 * - Moving state updates after external calls is a subtle but dangerous pattern
 * - The allowance mechanism creates persistent state that can be exploited
 * - Requires multiple transactions to fully exploit the allowance manipulation
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Corrected interface definition for ITokenReceiver
interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, address _caller) public;
}

contract BHTOKEN {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function BHTOKEN(
        ) public {
        totalSupply = 10000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "BH TOKEN";                                   // Set the name for display purposes
        symbol = "BHT";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Perform the transfer first
        _transfer(_from, _to, _value);
        // External call to recipient if it's a contract (potential reentrancy point)
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            ITokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
        }
        // State update moved AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
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
}
