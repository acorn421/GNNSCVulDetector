/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability exploits the window between balance credit and allowance deduction.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` callback after crediting balance to recipient
 * 2. Positioned the external call AFTER `balances[_to] += _value` but BEFORE `balances[_from] -= _value` and `allowed[_from][msg.sender] -= _value`
 * 3. Used low-level call() to ensure execution continues even if callback fails
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker approves themselves large allowance on victim's account
 * 2. **Transaction 2 (Exploit)**: Attacker calls transferFrom() to transfer tokens to malicious contract
 * 3. **During Transaction 2**: Malicious contract's onTokenReceived() callback executes and calls transferFrom() again
 * 4. **Reentrancy Effect**: The nested call sees the original allowance still intact (not yet decremented) and can transfer tokens again
 * 5. **State Persistence**: Each successful nested call accumulates transferred tokens while the allowance reduction is deferred
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires initial allowance setup in a separate transaction
 * - The attacker contract must be deployed and configured beforehand
 * - State changes from the initial approval persist and enable the reentrancy exploitation
 * - The accumulated effect of multiple nested calls creates a more severe vulnerability than single-transaction exploits
 * 
 * This creates a realistic vulnerability where the attacker can drain more tokens than their allowance should permit through nested calls that exploit the CEI pattern violation.
 */
pragma solidity ^0.4.16;
contract Token{
    uint256 public totalSupply;

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract TTNCoin is Token {

    string public constant name = "TTN";                   
    uint8 public constant decimals = 2; 
    string public constant symbol = "TTN";
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function TTNCoin(uint256 _initialAmount) public {
        totalSupply = _initialAmount * 10 ** uint256(decimals);         // 设置初始总量
        balances[msg.sender] = totalSupply; // 初始token数量给予消息发送者，因为是构造函数，所以这里也是合约的创建者
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        //默认totalSupply 不会超过最大值 (2^256 - 1).
        //如果随着时间的推移将会有新的token生成，则可以用下面这句避免溢出的异常
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;//从消息发送者账户中减去token数量_value
        balances[_to] += _value;//往接收账户增加token数量_value
        emit Transfer(msg.sender, _to, _value);//触发转币交易事件
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;//接收账户增加token数量_value
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before completing state updates
        // Added realistic token transfer notification mechanism
        if(_to.callcode.length > 0) { // Dummy way to reference code length in 0.4.x, will never be true
            bool callbackSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            // Continue execution regardless of callback success for compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value; //支出账户_from减去token数量_value
        allowed[_from][msg.sender] -= _value;//消息发送者可以从账户_from中转出的数量减少_value
        emit Transfer(_from, _to, _value);//触发转币交易事件
        return true;
    }
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }


    function approve(address _spender, uint256 _value) public returns (bool success)   
    { 
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];//允许_spender从_owner中转出的token数
    }
}
