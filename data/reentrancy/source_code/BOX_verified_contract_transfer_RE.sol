/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state changes. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract recipients using `_to.code.length > 0`
 * 2. Introduced an external call to `_to.call()` after balance updates are completed
 * 3. Added error handling that reverts state changes if the notification fails
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * Transaction 1: Attacker sets up a malicious contract with specific balance conditions and prepares the exploit
 * Transaction 2: Attacker initiates transfer to their malicious contract, which triggers the external call
 * Transaction 3+: During the external call, the malicious contract can re-enter the transfer function multiple times, draining funds incrementally
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker needs to deploy and prepare their malicious contract first
 * - The vulnerability exploits the persistent state changes (balance updates) that occur before the external call
 * - Multiple re-entrant calls are needed to gradually drain significant funds due to balance checks
 * - The state persists between transactions, allowing accumulated exploitation across calls
 * 
 * **Realistic Integration:**
 * This pattern mimics real-world token contracts that notify recipients about incoming transfers, making it a subtle but dangerous vulnerability that could realistically appear in production code.
 */
pragma solidity ^0.4.16;

// Copyright 2017. box.la authors.
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract BOX {
    string public constant symbol = "BOX";
    string public constant name = "BOX Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = (10 ** 8) * (10 ** 18);

    address public owner;

    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;

    // Constructor
    constructor() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    // Send back ether sent to me
    function () public {
        revert();
    }

    function totalSupply() constant public returns (uint256) {
        return _totalSupply;
    }
    
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }

    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            emit Transfer(msg.sender, _to, _amount);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient about the transfer - introduces reentrancy vulnerability
            if (extcodesize(_to) > 0) {
                // External call after state changes - classic reentrancy pattern
                bool notifySuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount);
                if (!notifySuccess) {
                    // If notification fails, revert the state changes
                    balances[msg.sender] += _amount;
                    balances[_to] -= _amount;
                    return false;
                }
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            emit Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Assembly function to get code size for extcodesize workaround
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
