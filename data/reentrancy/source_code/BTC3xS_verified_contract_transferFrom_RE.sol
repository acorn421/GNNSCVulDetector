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
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack by adding a callback mechanism to smart contract recipients. The vulnerability enables the following multi-transaction exploitation pattern:
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements the `onTokenReceived` callback. This contract is designed to re-enter the `transferFrom` function when called.
 * 
 * **Transaction 2 (Initial Call)**: Attacker calls `transferFrom` with their malicious contract as the recipient. The function updates balances, calls the malicious contract's callback, but the allowance update happens AFTER the external call.
 * 
 * **Transaction 3 (Reentrancy)**: During the callback, the malicious contract calls `transferFrom` again. Since the allowance hasn't been updated yet from the previous call, the checks pass again, allowing double-spending of the same allowance.
 * 
 * **State Persistence**: The key issue is that the allowance state is only updated after the external call, creating a window where the same allowance can be used multiple times across different transactions or reentrant calls.
 * 
 * **Multi-Transaction Requirement**: The vulnerability requires multiple transactions because:
 * 1. The malicious contract must be deployed first
 * 2. The initial `transferFrom` call must complete partially
 * 3. The reentrant call exploits the stale allowance state
 * 4. Each step depends on state changes from previous transactions
 * 
 * The attack leverages the fact that allowance updates occur after external calls, violating the checks-effects-interactions pattern and creating a race condition that persists across transaction boundaries.
 */
pragma solidity ^0.4.4;
contract SafeMath {
    // 乘法（internal修饰的函数只能够在当前合约或子合约中使用）
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) { 
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }
  
    // 除法
    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }
 
    // 减法
    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        assert(b >=0);
        return a - b;
    }
 
    // 加法
    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}
 
contract BTC3xS is SafeMath{
    // 代币的名字
    string public name; 
    // 代币的符号
    string public symbol;
    // 代币支持的小数位
    uint8 public decimals;
    // 代表发行的总量
    uint256 public totalSupply;
    // 管理者
    address public owner;
 
    // 该mapping保存账户余额，Key表示账户地址，Value表示token个数
    mapping (address => uint256) public balanceOf;
    // 该mappin保存指定帐号被授权的token个数
    // key1表示授权人，key2表示被授权人，value2表示被授权token的个数
    mapping (address => mapping (address => uint256)) public allowance;
    // 冻结指定帐号token的个数
    mapping (address => uint256) public freezeOf;
 
    // 定义事件
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Freeze(address indexed from, uint256 value);
    event Unfreeze(address indexed from, uint256 value);
 
    // 构造函数（1000000, "ZhongB", 18, "ZB"）
    constructor( 
        uint256 initialSupply,  // 发行数量
        string tokenName,       // token的名字 BinanceToken
        uint8 decimalUnits,     // 最小分割，小数点后面的尾数 1ether = 10** 18wei
        string tokenSymbol      // ZB
    ) public {
        decimals = decimalUnits;                           
        balanceOf[msg.sender] = initialSupply * 10 ** 18;    
        totalSupply = initialSupply * 10 ** 18;   
        name = tokenName;      
        symbol = tokenSymbol;
        owner = msg.sender;
    }
    
    //增发
    function mintToken(address _to, uint256 _value) public returns (bool success){
        // 防止_to无效
        assert(_to != 0x0);
        // 防止_value无效                       
        assert(_value > 0);
        balanceOf[_to] += _value;
        totalSupply += _value;
        emit Transfer(0, msg.sender, _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
 
    // 转账：某个人花费自己的币
    function transfer(address _to, uint256 _value) public {
        // 防止_to无效
        assert(_to != 0x0);
        // 防止_value无效                       
        assert(_value > 0);
        // 防止转账人的余额不足
        assert(balanceOf[msg.sender] >= _value);
        // 防止数据溢出
        assert(balanceOf[_to] + _value >= balanceOf[_to]);
        // 从转账人的账户中减去一定的token的个数
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     
        // 往接收帐号增加一定的token个数
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
        // 转账成功后触发Transfer事件，通知其他人有转账交易发生
        emit Transfer(msg.sender, _to, _value);// Notify anyone listening that this transfer took place
    }
 
    // 授权：授权某人花费自己账户中一定数量的token
    function approve(address _spender, uint256 _value) public returns (bool success) {
        assert(_value > 0);
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    // 授权转账：被授权人从_from帐号中给_to帐号转了_value个token
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        // 防止地址无效
        assert(_to != 0x0);
        // 防止转账金额无效
        assert(_value > 0);
        // 检查授权人账户的余额是否足够
        assert(balanceOf[_from] >= _value);
        // 检查数据是否溢出
        assert(balanceOf[_to] + _value >= balanceOf[_to]);
        // 检查被授权人在allowance中可以使用的token数量是否足够
        assert(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // 从授权人帐号中减去一定数量的token
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); 
        // 往接收人帐号中增加一定数量的token
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // 通知接收方有新的token到账 - 支持智能合约接收方的回调
        if(_isContract(_to)) {
            // 调用接收方合约的回调函数
            if(!_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value)) {
                revert();
            }
        }
        
        // 从allowance中减去被授权人可使用token的数量 - 在外部调用后更新
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // 交易成功后触发Transfer事件，并返回true
        emit Transfer(_from, _to, _value);
        return true;
    }

    // 冻结
    function freeze(uint256 _value) public returns (bool success) {
        // 检查账户余额是否足够
        assert(balanceOf[msg.sender] >= _value);
        // 只允许冻结正数
        assert(_value > 0); 
        // 从余额中减少
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); 
        // 增加冻结额
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); 
        emit Freeze(msg.sender, _value);
        return true;
    }
 
    // 解冻
    function unfreeze(uint256 _value) public returns (bool success) {
        // 检查解冻金额是否有效
        assert(freezeOf[msg.sender] >= _value);
        // 检查_value是否有效
        assert(_value > 0); 
        // 从freezeOf中减去指定sender账户一定数量的token
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value); 
        // 向sender账户中增加一定数量的token
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);    
        // 解冻成功后触发事件
        emit Unfreeze(msg.sender, _value);
        return true;
    }
 
    // 管理者自己取钱
    function withdrawEther(uint256 amount) public {
        // 检查sender是否是当前合约的管理者
        assert(msg.sender == owner);
        // sender给owner发送token
        owner.transfer(amount);
    }

    // Helper function to check if address is a contract (Solidity 0.4 style)
    function _isContract(address addr) internal view returns(bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
