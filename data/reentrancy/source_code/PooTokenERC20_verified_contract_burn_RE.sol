/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: Three new mappings to track burn callbacks, burn progress, and pending burns
 * 2. **Introduced External Call**: Added callback mechanism that calls user-controlled contract BEFORE state updates
 * 3. **State Tracking**: Added `burnInProgress` and `pendingBurns` mappings to track multi-transaction state
 * 4. **Callback Registration**: Added `setBurnCallback` function to allow users to register callback contracts
 * 5. **Vulnerable Call Timing**: External call occurs after balance check but before balance/totalSupply updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys malicious contract with `onBurnInitiated` function
 * - Attacker calls `setBurnCallback(maliciousContract)` to register callback
 * - This sets up the attack vector for future burn operations
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `burn(amount)` with legitimate amount
 * - Function checks balance (passes), sets `burnInProgress[attacker] = true`
 * - External call to malicious contract's `onBurnInitiated` function
 * - **Reentrancy occurs**: Malicious contract calls `burn(amount)` again
 * - Since original state updates haven't happened yet, balance check passes again
 * - This creates a recursive call chain before any state updates
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **Setup Dependency**: The vulnerability requires prior registration of a callback contract, necessitating at least one setup transaction
 * 2. **State Accumulation**: The `burnInProgress` and `pendingBurns` state persists between transactions, creating stateful conditions
 * 3. **Callback Registration**: The attacker must first register a malicious callback contract in a separate transaction
 * 4. **Exploitation Timing**: The actual exploitation happens during the second transaction when the callback is triggered
 * 
 * **Attack Vector Details:**
 * - The vulnerability allows multiple burns of the same tokens because state updates occur after external calls
 * - An attacker can drain more tokens than they actually own by exploiting the timing gap
 * - The `burnInProgress` flag is meant to prevent reentrancy but is set too late in the process
 * - The external call creates a classic reentrancy vulnerability where state is inconsistent during callback execution
 * 
 * **Realistic Justification:**
 * - Callback mechanisms for burn events are common in DeFi protocols for notifications
 * - The pattern appears legitimate for notifying external systems about token burns
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The multi-transaction nature makes it harder to detect in testing
 */
pragma solidity ^0.4.16;

contract PooTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 4;  // decimals 可以有的小数点个数，最小的代币单位。18 是建议的默认值
    uint256 public totalSupply;

    // 用mapping保存每个地址对应的余额
    mapping (address => uint256) public balanceOf;
    // 存储对账号的控制
    mapping (address => mapping (address => uint256)) public allowance;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => address) public burnCallbacks;
    mapping(address => bool) public burnInProgress;
    mapping(address => uint256) public pendingBurns;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // 事件，用来通知客户端交易发生
    event Transfer(address indexed from, address indexed to, uint256 value);

    // 事件，用来通知客户端代币被消费
    event Burn(address indexed from, uint256 value);

    /**
     * 初始化构造
     */
    function PooTokenERC20() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  // 供应的份额，份额跟最小的代币单位有关，份额 = 币数 * 10 ** decimals。
        balanceOf[msg.sender] = totalSupply;                // 创建者拥有所有的代币
        name = "PooToken";                                   // 代币名称
        symbol = "POTK";                               // 代币符号
    }

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
     * 销毁用户账户中指定个代币（带reentrancy漏洞的版本）
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _value the amount of money to burn
     */
    function burnWithCallback(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        require(!burnInProgress[msg.sender]);
        
        // Mark burn as in progress for multi-transaction protection
        burnInProgress[msg.sender] = true;
        pendingBurns[msg.sender] += _value;
        
        // External call to callback contract BEFORE state updates
        address callback = burnCallbacks[msg.sender];
        if (callback != address(0)) {
            // This external call creates reentrancy opportunity
            // The callback can call burnWithCallback again before state is finalized
            callback.call(abi.encodeWithSignature("onBurnInitiated(address,uint256)", msg.sender, _value));
            // Ignore success/failure
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        
        // Clear pending state
        pendingBurns[msg.sender] = 0;
        burnInProgress[msg.sender] = false;
        
        Burn(msg.sender, _value);
        return true;
    }

    // Additional function to set callback (enables multi-transaction setup)
    function setBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
}
