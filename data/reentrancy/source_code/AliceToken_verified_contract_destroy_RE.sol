/*
 * ===== SmartInject Injection Details =====
 * Function      : destroy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Partial State Update**: Modified the order to update balances[_from] first, before the external call
 * 2. **External Call Introduction**: Added a call to _from.call() to notify the address about token destruction
 * 3. **Delayed State Completion**: Moved totalSupply update to after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Owner calls destroy(attackerContract, 1000)
 * - balances[attackerContract] reduced by 1000
 * - External call triggers attackerContract.onTokenDestroy()
 * - AttackerContract can now observe inconsistent state: their balance is reduced but totalSupply is unchanged
 * 
 * **Transaction 2 (Exploitation):**
 * - During the callback in Transaction 1, attackerContract calls other functions (transfer, mint, etc.)
 * - These functions operate on inconsistent state where balances[_from] is already decremented but totalSupply hasn't been updated yet
 * - This creates opportunities for double-spending or bypassing total supply constraints
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The attacker can leverage the temporarily inconsistent state to perform operations that shouldn't be possible
 * - For example, mint operations might succeed when they should fail due to supply constraints
 * - Transfer operations might behave unexpectedly due to the inconsistent accounting
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger a reentrant callback
 * - The callback must be able to call back into the contract during the inconsistent state window
 * - This creates a sequence where state is partially updated in one transaction context, exploited in a nested transaction context, and then completed in the original context
 * - Single-transaction exploitation is impossible because the reentrancy occurs during the execution of the destroy function itself, requiring the callback mechanism to trigger the vulnerability
 */
/*
Implements ERC 20 Token standard: https://github.com/ethereum/EIPs/issues/20
*/

pragma solidity ^0.4.2;

// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/issues/20
pragma solidity ^0.4.2;

contract Token {
    /* This is a slight change to the ERC20 base standard.
    function totalSupply() constant returns (uint256 supply);
    is replaced with:
    uint256 public totalSupply;
    This automatically creates a getter function for the totalSupply.
    This is moved to the base contract since public getter functions are not
    currently recognised as an implementation of the matching abstract
    function by the compiler.
    */
    /// total amount of tokens
    uint256 public totalSupply;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) constant returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transfer(address _to, uint256 _value);

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transferFrom(address _from, address _to, uint256 _value);

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

pragma solidity ^0.4.2;

contract Owned {

	address owner;

	function Owned() {
		owner = msg.sender;
	}

	modifier onlyOwner {
        if (msg.sender != owner)
            throw;
        _;
    }
}


contract AliceToken is Token, Owned {

    string public name = "Alice Token";
    uint8 public decimals = 2;
    string public symbol = "ALT";
    string public version = 'ALT 1.0';


    function transfer(address _to, uint256 _value) {
        //Default assumes totalSupply can't be over max (2^256 - 1).
        if (balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
        } else { throw; }
    }

    function transferFrom(address _from, address _to, uint256 _value) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        } else { throw; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function mint(address _to, uint256 _value) onlyOwner {
        if (totalSupply + _value < totalSupply) throw;
            totalSupply += _value;
            balances[_to] += _value;

            MintEvent(_to, _value);
    }

    function destroy(address _from, uint256 _value) onlyOwner {
        if (balances[_from] < _value || _value < 0) throw;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balance first (partial state update)
        balances[_from] -= _value;
        
        // External call to notify the affected address - potential reentrancy point
        if (_from.call(bytes4(keccak256("onTokenDestroy(uint256)")), _value)) {
            // Callback successful - in a reentrancy scenario, the reentrant call
            // can observe the updated balance but unchanged totalSupply
        }
        
        // Complete state update after external call (violates CEI pattern)
        totalSupply -= _value;
        DestroyEvent(_from, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event MintEvent(address indexed to, uint value);
    event DestroyEvent(address indexed from, uint value);
}