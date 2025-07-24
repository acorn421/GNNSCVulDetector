/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts after state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` after balance updates but before function return
 * 2. The call invokes `onTokenReceived()` on recipient contracts
 * 3. No reentrancy guards or checks-effects-interactions pattern protection
 * 4. Call result is ignored for "compatibility" reasons
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract implementing `onTokenReceived()`
 * 2. **Initial Transfer**: Legitimate user transfers tokens to malicious contract
 * 3. **Reentrancy Chain**: Malicious contract's `onTokenReceived()` calls back to `transfer()` before initial transaction completes
 * 4. **State Exploitation**: Multiple transfers can occur using the same balance state
 * 5. **Accumulation**: Repeated reentrant calls can drain more tokens than originally held
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires setup of a malicious contract (separate deployment transaction)
 * - Exploitation depends on accumulated state from legitimate user interactions
 * - The attack chain spans multiple nested calls that modify persistent contract state
 * - Balance state changes accumulate across the reentrant call sequence
 * 
 * **Realistic Integration:**
 * - Token recipient notification is a common pattern in modern tokens
 * - The external call placement after state updates is a typical mistake
 * - Ignoring call results appears to maintain compatibility but enables exploitation
 * - The vulnerability manifests when transferring to contract addresses that implement callbacks
 */
pragma solidity ^0.4.8;

// ----------------------------------------------------------------------------------------------
// Comet DeFi token smart contract
// ----------------------------------------------------------------------------------------------

// ERC Token Standard #20 Interface
contract ERC20Interface {
    // Get the total token supply
    function totalSupply() constant returns (uint256 totalSupply);

    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256 balance);

    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _amount) returns (bool success);

    // Send _value amount of tokens from address _from to address _to
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    // this function is required for some DEX functionality
    function approve(address _spender, uint256 _value) returns (bool success);

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);

    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract FixedSupplyToken is ERC20Interface {
    string public constant symbol = "CMT";
    string public constant name = "Cometa";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 10000000000000000000000000;
    
    // Owner of this contract
    address public owner;

    // Balances for each account
    mapping(address => uint256) balances;

    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;

    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }

    // Constructor
    function FixedSupplyToken() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256) {
        return _totalSupply;
    }

    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Transfer method with injected reentrancy vulnerability
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            // Notify recipient contract of token receipt
            if (isContract(_to)) {
                // Inline assembly to call code length as .code.length is invalid pre-0.8.0
                // Fallback to extcodesize
                uint256 length;
                address addr = _to;
                assembly { length := extcodesize(addr) }
                if (length > 0) {
                    _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount);
                }
            }
            return true;
        } else {
            return false;
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // Helper to detect contract code size
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
