/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts with pending transfer state management. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker calls transfer() to a malicious contract, which receives the onTokenReceived callback. During this callback, the attacker can call other contract functions (like transfer again) since balances are already updated but the transaction hasn't completed.
 * 
 * 2. **Transaction 2**: If the callback fails, the transfer gets marked as "pending" with state stored in pendingTransfers mapping. The attacker can then exploit this pending state in subsequent transactions to manipulate the contract's accounting.
 * 
 * 3. **Multi-Transaction Exploitation**: The attacker can accumulate multiple pending transfers across different transactions, then exploit the inconsistent state between actual balances and pending transfer records.
 * 
 * The vulnerability is stateful because:
 * - pendingTransfers mapping persists between transactions
 * - pendingTransferCount tracks accumulated failed transfers
 * - The contract maintains inconsistent state between successful balance updates and failed callback handling
 * 
 * This creates a race condition where the attacker can manipulate the contract state through multiple transactions, using the external call as a vector to trigger additional contract interactions while the transfer is in an intermediate state.
 */
pragma solidity ^0.4.8;
 
// ----------------------------------------------------------------------------------------------
// Sample fixed supply token contract
// Enjoy. (c) BokkyPooBah 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------
 
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract ERC20Interface {
    // State variable declarations moved from interface to base contract (Solidity limitation)
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => mapping(address => uint256)) pendingTransfers; // <-- declared for injected code
    mapping(address => uint256) pendingTransferCount;                // <-- declared for injected code

    // Get the total token supply
    function totalSupply() constant returns (uint256 supply);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256 balance);
 
    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

            // Notify recipient contract of token transfer (vulnerable external call)
            uint length;
            assembly {
                length := extcodesize(_to)
            }
            if (length > 0) {
                bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
                if (!callSuccess) {
                    // On callback failure, create pending transfer state
                    pendingTransfers[msg.sender][_to] = _amount;
                    pendingTransferCount[msg.sender]++;
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
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
 
contract FuturecomToken is ERC20Interface {
    string public constant symbol = "FUCOS";
    string public constant name = "Futurecom Interactive Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 42000000000000000000000000;
    
    // Owner of this contract
    address public owner;
 
    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }
 
    // Constructor
    function FuturecomToken() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
 
    function totalSupply() constant returns (uint256 supply) {
        supply = _totalSupply;
    }
 
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }
 
    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
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
