/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability. The vulnerability manifests through a token locking mechanism where users can lock tokens for a specific duration and release them after the lock period expires. The critical flaw is the reliance on block.timestamp for time-sensitive operations. The vulnerability requires multiple transactions to exploit: first calling lockTokens() to establish the locked state, then potentially manipulating block timestamps through mining, and finally calling releaseLocked() to exploit the timing manipulation. The state (lockedTokens, lockReleaseTime) persists between transactions, making this a classic stateful vulnerability that cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.16;

contract SusanTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 4;  // decimals 可以有的小数点个数，最小的代币单位。18 是建议的默认值
    uint256 public totalSupply;

    // 用mapping保存每个地址对应的余额
    mapping (address => uint256) public balanceOf;
    // 存储对账号的控制
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Added mapping declarations here, outside constructor, to fix syntax
    mapping (address => uint256) public lockedTokens;
    mapping (address => uint256) public lockReleaseTime;
    // === END DECLARATIONS ===

    // 事件，用来通知客户端交易发生
    event Transfer(address indexed from, address indexed to, uint256 value);

    // 事件，用来通知客户端代币被消费
    event Burn(address indexed from, uint256 value);

    /**
     * 初始化构造
     */
    function SusanTokenERC20() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  // 供应的份额，份额跟最小的代币单位有关，份额 = 币数 * 10 ** decimals。
        balanceOf[msg.sender] = totalSupply;                // 创建者拥有所有的代币
        name = "SusanToken";                                   // 代币名称
        symbol = "SUTK";                               // 代币符号
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Lock tokens for a specific period
     * @param _amount Amount of tokens to lock
     * @param _lockDuration Duration in seconds to lock tokens
     */
    function lockTokens(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_lockDuration > 0);
        
        balanceOf[msg.sender] -= _amount;
        lockedTokens[msg.sender] += _amount;
        
        // Vulnerable: Using block.timestamp for time-sensitive operations
        lockReleaseTime[msg.sender] = block.timestamp + _lockDuration;
        
        return true;
    }
    
    /**
     * Release locked tokens if lock period has expired
     */
    function releaseLocked() public returns (bool success) {
        require(lockedTokens[msg.sender] > 0);
        
        // Vulnerable: Miners can manipulate block.timestamp within reasonable bounds
        // This creates a multi-transaction vulnerability where:
        // 1. User calls lockTokens() to lock tokens
        // 2. Malicious miner can manipulate subsequent block timestamps
        // 3. User calls releaseLocked() potentially earlier than intended
        require(block.timestamp >= lockReleaseTime[msg.sender]);
        
        uint256 amount = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;
        balanceOf[msg.sender] += amount;
        
        return true;
    }
    
    /**
     * Emergency release with penalty (admin function)
     */
    function emergencyRelease() public returns (bool success) {
        require(lockedTokens[msg.sender] > 0);
        
        uint256 amount = lockedTokens[msg.sender];
        uint256 penalty = 0;
        
        // Additional vulnerability: Time-based penalty calculation
        if (block.timestamp < lockReleaseTime[msg.sender]) {
            // 10% penalty for early release
            penalty = amount / 10;
            amount -= penalty;
            // Penalty tokens are burned
            totalSupply -= penalty;
        }
        
        lockedTokens[msg.sender] = 0;
        balanceOf[msg.sender] += amount;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /**
     * 代币交易转移的内部实现
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // 确保目标地址不为0x0，因为0x0地址代表销毁
        require(_to != 0x0);
        // 检查发送者余额
        require(balanceOf[_from] >= _value);
        // 确保转移为正数个
        require(balanceOf[_to] + _value > balanceOf[_to]);

        // 以下用来检查交易，
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);

        // 用assert来检查代码逻辑。
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     *  代币交易转移
     * 从自己（创建交易者）账号发送`_value`个代币到 `_to`账号
     *
     * @param _to 接收者地址
     * @param _value 转移数额
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * 账号之间代币交易转移
     * @param _from 发送者地址
     * @param _to 接收者地址
     * @param _value 转移数额
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * 设置某个地址（合约）可以创建交易者名义花费的代币数。
     *
     * 允许发送者`_spender` 花费不多于 `_value` 个代币
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * 销毁我（创建交易者）账户中指定个代币
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * 销毁用户账户中指定个代币
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }

   function mintToken(address target, uint256 initialSupply) public{
        balanceOf[target] += initialSupply;
        totalSupply += initialSupply;
        Transfer(0, msg.sender, initialSupply);
        Transfer(msg.sender, target,initialSupply);
    }
}
