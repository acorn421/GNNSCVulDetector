/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call**: Introduced a callback mechanism that calls a user-controlled contract (`freezeCallback[msg.sender]`) after state updates but before event emission
 * 2. **Violation of CEI Pattern**: The external call occurs after state modifications (`balanceOf` and `freezeOf` updates) but before the function completes
 * 3. **Realistic Integration**: The callback appears as a legitimate notification feature for freeze operations
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious callback contract
 * - Calls `setFreezeCallback()` to register the malicious contract
 * - This transaction establishes the persistent state needed for exploitation
 * 
 * **Transaction 2 (Initial Freeze):**
 * - Attacker calls `freeze()` with initial value
 * - State is updated: `balanceOf` decreased, `freezeOf` increased
 * - External callback is triggered, allowing reentrancy
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - Inside the callback, attacker re-enters `freeze()` function
 * - Since state was already modified in Transaction 2, the checks may pass with manipulated values
 * - Multiple reentrant calls can manipulate the accumulated frozen balance
 * - Each reentrant call represents a separate logical transaction within the callback
 * 
 * **Why Multi-Transaction Requirement:**
 * 
 * 1. **State Persistence**: The `freezeCallback` mapping must be set in a previous transaction to enable the vulnerability
 * 2. **Accumulated State**: Each freeze operation builds upon previous frozen amounts, requiring multiple calls to achieve significant impact
 * 3. **Realistic Attack Vector**: Real attackers would need to:
 *    - Deploy callback contract (Transaction 1)
 *    - Register callback (Transaction 2) 
 *    - Execute freeze with reentrancy (Transaction 3+)
 * 4. **State Dependencies**: The vulnerability depends on the accumulated state from previous freeze operations, making single-transaction exploitation impossible
 * 
 * **Exploitation Impact:**
 * - Attacker can freeze more tokens than they actually have
 * - Multiple reentrant calls can manipulate the frozen balance calculations
 * - The vulnerability requires multiple transactions to set up and exploit effectively
 * - State changes persist between transactions, enabling progressive exploitation
 */
pragma solidity ^0.4.4;

interface IFreezeCallback {
    function onFreeze(address from, uint256 value) external;
}

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

    // 回调地址
    mapping (address => address) public freezeCallback;
 
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
        // 从授权人帐号中减去一定数量的token
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); 
        // 往接收人帐号中增加一定数量的token
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
        // 从allowance中减去被授权人可使用token的数量
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        // 交易成功后触发Transfer事件，并返回true
        emit Transfer(_from, _to, _value);
        return true;
    }
 
    // 消毁币
    function burn(uint256 _value) public returns (bool success) {
        // 检查当前帐号余额是否足够
        assert(balanceOf[msg.sender] >= _value);
        // 检查_value是否有效
        assert(_value > 0);
        // 从sender账户中中减去一定数量的token
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // 更新发行币的总量
        totalSupply = SafeMath.safeSub(totalSupply,_value);
        // 消币成功后触发Burn事件，并返回true
        emit Burn(msg.sender, _value);
        return true;
    }
 
    // 冻结
    function freeze(uint256 _value) public returns (bool success) {
        // 检查sender账户余额是否足够
        assert(balanceOf[msg.sender] >= _value);
        // 检查_value是否有效
        assert(_value > 0);
        // 从sender账户中减去一定数量的token
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); 
        // 往freezeOf中给sender账户增加指定数量的token
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external contract about freeze operation (vulnerable external call)
        if (freezeCallback[msg.sender] != address(0)) {
            IFreezeCallback(freezeCallback[msg.sender]).onFreeze(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // freeze成功后触发Freeze事件，并返回true
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
        // unfreeze成功后触发Unfreeze事件，并返回true
        emit Unfreeze(msg.sender, _value);
        return true;
    }
}
