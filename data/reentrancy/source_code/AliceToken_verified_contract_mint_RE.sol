/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a low-level call to `_to.call()` that executes before the critical state variables (`totalSupply` and `balances[_to]`) are updated.
 * 
 * 2. **Callback Mechanism**: Added a realistic callback mechanism that calls `onTokenMint(uint256)` on the recipient contract if it contains code, simulating a common pattern where contracts notify recipients of incoming tokens.
 * 
 * 3. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs between the checks (overflow validation) and the effects (state updates), creating a reentrancy window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `onTokenMint(uint256)`
 * - The malicious contract's `onTokenMint` function calls back to `mint()` with different parameters
 * - During this first transaction, the external call triggers but the reentrancy attempt fails due to the `onlyOwner` modifier
 * 
 * **Transaction 2 (Exploitation):**
 * - Owner legitimately calls `mint()` with the malicious contract as `_to`
 * - The external call triggers `onTokenMint()` on the malicious contract
 * - The malicious contract re-enters `mint()` before the original state updates complete
 * - Since `totalSupply` and `balances[_to]` haven't been updated yet, the overflow check passes with stale values
 * - Multiple mint operations can be executed with the same pre-state validation
 * - State accumulates incorrectly across the nested calls
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability exploits the fact that state changes persist between transactions, allowing the attacker to set up malicious contracts in earlier transactions.
 * 
 * 2. **Authorization Dependency**: The `onlyOwner` modifier means the attacker cannot directly exploit the vulnerability - they must wait for the owner to call `mint()` with their malicious contract as the recipient.
 * 
 * 3. **Contract Deployment Requirement**: The attacker must first deploy a malicious contract with the `onTokenMint` callback, which requires a separate transaction from the exploitation.
 * 
 * 4. **Reentrancy Window**: The vulnerability only becomes effective when the external call is made to a prepared malicious contract, requiring the sequence of: deploy malicious contract → owner calls mint with malicious contract address.
 * 
 * **Exploitation Impact:**
 * - Allows minting of tokens beyond intended amounts
 * - Can manipulate `totalSupply` and `balances` in ways that violate token economics
 * - Creates inconsistent state where the sum of individual balances may not equal `totalSupply`
 * - Enables potential inflation attacks on the token supply
 */
/*
Implements ERC 20 Token standard: https://github.com/ethereum/EIPs/issues/20
*/

pragma solidity ^0.4.2;

// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/issues/20

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

contract Owned {

    address owner;

    function Owned() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming tokens before state update
        if(isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenMint(uint256)")), _value);
        }
        
        totalSupply += _value;
        balances[_to] += _value;

        MintEvent(_to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function destroy(address _from, uint256 _value) onlyOwner {
        if (balances[_from] < _value || _value < 0) throw;
            totalSupply -= _value;
            balances[_from] -= _value;

            DestroyEvent(_from, _value);
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event MintEvent(address indexed to, uint value);
    event DestroyEvent(address indexed from, uint value);

    // Helper function to detect if an address is a contract
    function isContract(address _addr) internal constant returns (bool) {
        uint codeLength;
        assembly { codeLength := extcodesize(_addr) }
        return codeLength > 0;
    }
}
