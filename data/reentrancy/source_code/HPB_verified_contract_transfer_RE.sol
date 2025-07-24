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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient contract before completing the balance update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` after reducing sender's balance but before updating recipient's balance
 * 2. The call invokes `onTokenReceived()` function on the recipient contract
 * 3. The external call occurs in the middle of the state update process, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract with `onTokenReceived()` callback
 * 2. **Transaction 2 (Initial Transfer)**: Legitimate user calls `transfer()` to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived()` callback is triggered
 * 4. **Reentrancy Window**: Inside the callback, the attacker can call `transfer()` again while the original transfer is still in progress
 * 5. **State Manipulation**: The attacker can drain balances by repeatedly calling transfer before the original balance updates complete
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy and configure the malicious contract (Transaction 1)
 * - The vulnerability can only be triggered when someone transfers tokens TO the malicious contract (Transaction 2+)
 * - The attack requires accumulated state changes across multiple reentrancy calls within the same transaction
 * - Each reentrant call modifies the persistent `balances` mapping, creating a chain of state manipulations
 * - The exploit builds up through multiple nested function calls, each depending on the state from previous calls
 * 
 * **Stateful Nature:**
 * - The `balances` mapping persists across all transactions and calls
 * - Each reentrancy call depends on the balance state left by previous calls
 * - The vulnerability exploits the gap between balance deduction and balance addition
 * - Multiple reentrant calls can compound the effect by repeatedly manipulating the same persistent state
 * 
 * This creates a realistic reentrancy vulnerability that requires careful setup and stateful exploitation across multiple transaction contexts.
 */
pragma solidity ^0.4.26;
contract HPB {
    address public owner;
    mapping (address => uint) public balances;
    address[] public users;
    uint256 public total=0;
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => mapping (address => uint256)) public allowed;
    uint256 public totalSupply=10000000000000000;
    string public name="Health Preservation Treasure";
    uint8 public decimals=8;
    string public symbol="HPT";
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public{
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    function userCount() public view returns (uint256) {
        return users.length;
    }

    function getTotal() public view returns (uint256) {
        return total;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function contractBalance() public view returns (uint256) {
        return this.balance;
    }
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // for compatibility with Solidity 0.4.x, use .call as before
            bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Recipient notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function() public payable {
        if (msg.value > 0 ) {
            total += msg.value;
            bool isfind=false;
            for(uint i=0;i<users.length;i++)
            {
                if(msg.sender==users[i])
                {
                    isfind=true;
                    break;
                }
            }
            if(!isfind){users.push(msg.sender);}
        }
    }
}