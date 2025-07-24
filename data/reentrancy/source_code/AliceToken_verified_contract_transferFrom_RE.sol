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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)` before state updates
 * 2. This violates the Checks-Effects-Interactions pattern by performing external interaction before updating critical state variables
 * 3. The external call allows the recipient contract to execute arbitrary code while the transferFrom function is in an intermediate state
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contract at address that will receive tokens
 * 2. **Transaction 2 (Initial Transfer)**: Legitimate user calls transferFrom to send tokens to attacker's contract
 * 3. **Reentrant Exploitation**: During the external call in Transaction 2, attacker's contract re-enters transferFrom (or other functions) multiple times before the original state updates complete
 * 4. **State Manipulation**: Attacker can exploit the inconsistent state where balances are checked but not yet updated across multiple nested calls
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single atomic transaction because it requires the attacker to first have a malicious contract deployed at the recipient address
 * - The exploit requires coordination between the external call trigger and the reentrant calls
 * - The attacker must accumulate state changes across multiple function invocations to drain funds effectively
 * - Each reentrant call builds upon the previous state, creating a cascading effect that requires multiple transaction contexts to be fully exploited
 * 
 * **Realistic Nature:**
 * - Adding transfer notifications/hooks is a common pattern in modern token contracts
 * - The external call appears legitimate as a recipient notification mechanism
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - Maintains all original functionality while introducing the security flaw
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

    // Add these declarations so that the interface defines them and derived contracts can use them
    mapping (address => uint256) internal balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public constant returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transfer(address _to, uint256 _value) public;

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transferFrom(address _from, address _to, uint256 _value) public {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract about incoming transfer before updating state
            if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                // External call completed, now update state
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        } else { revert(); }
    }

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) public returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining);

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
            revert();
        _;
    }
}

contract AliceToken is Token, Owned {

    string public name = "Alice Token";
    uint8 public decimals = 2;
    string public symbol = "ALT";
    string public version = 'ALT 1.0';


    function transfer(address _to, uint256 _value) public {
        //Default assumes totalSupply can't be over max (2^256 - 1).
        if (balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
        } else { revert(); }
    }

    function transferFrom(address _from, address _to, uint256 _value) public {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        } else { revert(); }
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function mint(address _to, uint256 _value) public onlyOwner {
        if (totalSupply + _value < totalSupply) revert();
        totalSupply += _value;
        balances[_to] += _value;

        MintEvent(_to, _value);
    }

    function destroy(address _from, uint256 _value) public onlyOwner {
        if (balances[_from] < _value) revert();
        totalSupply -= _value;
        balances[_from] -= _value;

        DestroyEvent(_from, _value);
    }

    // These are already declared in the base Token contract
    // mapping (address => uint256) balances;
    // mapping (address => mapping (address => uint256)) allowed;

    event MintEvent(address indexed to, uint value);
    event DestroyEvent(address indexed from, uint value);
}