/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at `_to` address using `_to.code.length > 0`
 * 2. Introduced an external call to `_to.call(abi.encodeWithSignature("onTokenMint(address,uint256)", msg.sender, _value))` BEFORE updating balanceOf and totalSupply
 * 3. The external call occurs before the critical state changes, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenMint` function
 * 2. **Transaction 2**: Attacker calls `mintToken` with their malicious contract as `_to`
 * 3. **During Transaction 2**: The external call triggers the malicious contract's `onTokenMint` function
 * 4. **Reentrancy**: The malicious contract calls `mintToken` again before the original state updates complete
 * 5. **State Persistence**: Each reentrant call increases `balanceOf` and `totalSupply` based on the old state
 * 6. **Accumulated Effect**: Multiple nested calls result in exponentially increased token amounts
 * 
 * **Why Multiple Transactions Are Required:**
 * - **Setup Phase**: The attacker must first deploy the malicious contract (Transaction 1)
 * - **Exploitation Phase**: The actual reentrancy occurs when calling mintToken (Transaction 2)
 * - **State Accumulation**: The vulnerability exploits the persistent state changes across the nested calls within Transaction 2
 * - **Cross-Call Dependencies**: Each reentrant call depends on the accumulated state from previous calls in the same transaction
 * 
 * **Stateful Nature:**
 * - The vulnerability relies on persistent state variables (balanceOf, totalSupply) that maintain their values between calls
 * - Each reentrant call builds upon the state modifications from previous calls
 * - The exploit accumulates value across multiple nested function executions
 * 
 * This creates a realistic token minting notification system that introduces a subtle but dangerous reentrancy vulnerability requiring careful orchestration across multiple transactions.
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
        assert(b >= 0);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about incoming mint (external call before state update)
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // External call to recipient contract - potential reentrancy point
            _to.call(abi.encodeWithSignature("onTokenMint(address,uint256)", msg.sender, _value));
            // Continue even if call fails to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        totalSupply += _value;
        emit Transfer(0, msg.sender, _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
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
}
