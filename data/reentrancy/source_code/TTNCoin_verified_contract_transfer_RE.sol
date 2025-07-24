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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added a check for contract code at the recipient address using `_to.code.length > 0`
 * 2. Inserted an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before state modifications
 * 3. Added a require statement to ensure the call succeeds
 * 4. Maintained all original functionality and validation logic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to send tokens to their malicious contract
 * 2. **During Transaction 1**: The external call triggers the malicious contract's `onTokenReceived()` function
 * 3. **Transaction 2**: From within `onTokenReceived()`, the malicious contract calls `transfer()` again before the first transaction completes
 * 4. **State Inconsistency**: The attacker can exploit the window where balances haven't been updated yet from the first transaction
 * 5. **Accumulated Effect**: Multiple nested calls can drain more tokens than the attacker actually owns
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability relies on the persistent state of the `balances` mapping between calls
 * - Each nested transaction sees the original balance state before any updates occur
 * - The attacker must accumulate multiple transfer operations to exceed their actual balance
 * - The exploit cannot work in a single transaction because it depends on the callback mechanism and state persistence across multiple function invocations
 * - The external call creates a reentrancy window that spans multiple transaction contexts
 * 
 * This creates a realistic reentrancy vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.16;
contract Token{
    uint256 public totalSupply;
    mapping (address => uint256) balances;
    // 'allowed' is only used in TTNCoin, not needed in Token base

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success) {
        //默认totalSupply 不会超过最大值 (2^256 - 1).
        //如果随着时间的推移将会有新的token生成，则可以用下面这句避免溢出的异常
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of incoming transfer before state changes
        if (_to.delegatecall.gas(2300)()) {} // Do nothing, just to refer _to.code.length in Solidity <0.5
        // Inline workaround: can't use _to.code.length in 0.4, so skip this line in old syntax, or use extcodesize
        uint256 len;
        assembly { len := extcodesize(_to) }
        if (len > 0) {
            // direct use of call instead of ABI encoding in 0.4.x
            if(!_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
                revert();
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;//从消息发送者账户中减去token数量_value
        balances[_to] += _value;//往接收账户增加token数量_value
        Transfer(msg.sender, _to, _value);//触发转币交易事件
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns   
    (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);

    function allowance(address _owner, address _spender) public constant returns 
    (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 
    _value);
}

contract TTNCoin is Token {

    string public constant name = "TTN";                   
    uint8 public constant decimals = 2; 
    string public constant symbol = "TTN";

    mapping (address => mapping (address => uint256)) allowed;
    // Now balances is declared in base class (Token), OK

    constructor(uint256 _initialAmount) public {
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
        Transfer(msg.sender, _to, _value);//触发转币交易事件
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns 
    (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;//接收账户增加token数量_value
        balances[_from] -= _value; //支出账户_from减去token数量_value
        allowed[_from][msg.sender] -= _value;//消息发送者可以从账户_from中转出的数量减少_value
        Transfer(_from, _to, _value);//触发转币交易事件
        return true;
    }
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success)   
    { 
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];//允许_spender从_owner中转出的token数
    }
}
