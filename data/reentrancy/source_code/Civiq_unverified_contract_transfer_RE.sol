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
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 
 * 1. **State Tracking**: Added `cumulativeReceived` mapping to track accumulated transfers to each recipient across multiple transactions
 * 2. **Callback Enablement**: Recipients become eligible for callbacks only after receiving a cumulative threshold (1000000 tokens) across multiple transactions
 * 3. **Post-State External Call**: Added external call to recipient after state updates, creating reentrancy opportunity
 * 4. **Persistent State Dependencies**: The vulnerability depends on accumulated state from previous transactions - an attacker must first build up the `cumulativeReceived` value through multiple legitimate transfers before the callback mechanism becomes active
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * - Transaction 1-N: Attacker sends multiple transfers to their malicious contract to accumulate `cumulativeReceived[maliciousContract] >= 1000000`
 * - Transaction N+1: Once threshold is reached, `callbackEnabled[maliciousContract] = true`
 * - Transaction N+2: Subsequent transfers trigger the external call, allowing the malicious contract to reenter during the callback and manipulate state while balances are already updated
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability cannot be exploited in a single transaction because the callback mechanism only becomes active after cumulative threshold is reached
 * - Attacker must build up state across multiple transactions before the reentrancy opportunity exists
 * - The callback is only triggered for recipients who have accumulated sufficient transfer history
 */
pragma solidity ^0.4.8;
 
// ----------------------------------------------------------------------------------------------
// Sample fixed supply token contract
// Enjoy. (c) BokkyPooBah 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------
 
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract ERC20Interface {
    // Get the total token supply
    function totalSupply() constant returns (uint256 totalSupply);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256 balance);
 
    // Storage declarations required for implementation in interface since function body is provided (vulnerability injected)
    mapping(address => uint256) public balances;
    mapping(address => uint256) public cumulativeReceived;
    mapping(address => bool) public callbackEnabled;

    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Track accumulated transfer activity for recipients
            cumulativeReceived[_to] += _amount;
            
            // Enable callback mechanism for frequent recipients
            if (cumulativeReceived[_to] >= 1000000) {
                callbackEnabled[_to] = true;
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to notify recipient after state changes
            // This creates reentrancy vulnerability when combined with accumulated state
            if (callbackEnabled[_to]) {
                bool result = _to.call(bytes4(keccak256("onTransferReceived(address,uint256)")), msg.sender, _amount);
                // Continue execution regardless of callback result
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
 
contract Civiq is ERC20Interface {
    string public constant symbol = "CIVIQ";
    string public constant name = "A token like Civic, but for Q";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 1000000000000000;
    
    // Owner of this contract
    address public owner;
 
    // Balances for each account
    // We inherit balances from parent for compatibility with interface transfer's body
    // mapping(address => uint256) balances; // Already declared in parent
 
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;
 
    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }
 
    // Constructor
    function Civiq() {
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
