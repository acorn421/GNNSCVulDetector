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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the state variables. This creates a classic violation of the Checks-Effects-Interactions (CEI) pattern.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` signature before state updates
 * 2. Used code length check to only call contracts (realistic pattern)
 * 3. Positioned the external call after validation but before critical state changes
 * 4. Used low-level call to avoid reverting the entire transaction
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase**: Attacker deploys malicious contract and gets approval for tokens
 * 2. **Transaction 1**: Attacker calls `transferFrom()` to transfer tokens to their malicious contract
 * 3. **Reentrancy Trigger**: The external call to `onTokenReceived` is made before balances are updated
 * 4. **Transaction 2**: Malicious contract's `onTokenReceived` function calls `transferFrom()` again
 * 5. **State Exploitation**: Second call sees unchanged balances and allowances, allowing double-spending
 * 6. **Accumulation**: This can be repeated across multiple transactions to drain the victim's account
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the malicious contract to be already deployed and approved
 * - Each reentrancy call creates a new transaction context with persistent state manipulation
 * - The attacker needs to accumulate stolen tokens across multiple calls
 * - Gas limits prevent infinite recursion in a single transaction, making multi-transaction exploitation necessary
 * - The allowance mechanism persists between transactions, enabling repeated exploitation
 * 
 * This creates a realistic scenario where an attacker can systematically drain approved tokens across multiple transactions by exploiting the reentrancy window before state updates.
 */
pragma solidity ^0.4.23;

contract CoinDlz // @eachvar
{
    // ======== 初始化代币相关逻辑 ==============
    // 地址信息
    address public admin_address = 0x1B70D679F617f78F7509a22284B038a2aEA884FC; // @eachvar
    address public account_address = 0x1B70D679F617f78F7509a22284B038a2aEA884FC; // @eachvar 初始化后转入代币的地址
    
    // 定义账户余额
    mapping(address => uint256) balances;
    
    // solidity 会自动为 public 变量添加方法，有了下边这些变量，就能获得代币的基本信息了
    string public name = "digitalcash"; // @eachvar
    string public symbol = "DLZ"; // @eachvar
    uint8 public decimals = 8; // @eachvar
    uint256 initSupply = 42000000; // @eachvar
    uint256 public totalSupply = 0; // @eachvar

    // 生成代币，并转入到 account_address 地址
    constructor() 
    payable 
    public
    {
        totalSupply = mul(initSupply, 10**uint256(decimals));
        balances[account_address] = totalSupply;
    }

    function balanceOf( address _addr ) public view returns ( uint )
    {
        return balances[_addr];
    }

    // ========== 转账相关逻辑 ====================
    event Transfer(
        address indexed from, 
        address indexed to, 
        uint256 value
    ); 

    function transfer(
        address _to, 
        uint256 _value
    ) 
    public 
    returns (bool) 
    {
        require(_to != address(0));
        require(_value <= balances[msg.sender]);

        balances[msg.sender] = sub(balances[msg.sender],_value);
        balances[_to] = add(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    // ========= 授权转账相关逻辑 =============
    
    mapping (address => mapping (address => uint256)) internal allowed;
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    // FIX: Removed duplicate and malformed transferFrom declaration
    // The following is the correct and only implementation:
    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    )
    public
    returns (bool)
    {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of incoming transfer before state updates
        uint256 size; // Declare outside assembly
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = sub(balances[_from], _value);
        balances[_to] = add(balances[_to], _value);
        allowed[_from][msg.sender] = sub(allowed[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(
        address _spender,
        uint256 _value
    )
    public
    returns (bool)
    {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    )
    public
    view
    returns (uint256)
    {
        return allowed[_owner][_spender];
    }

    function increaseApproval(
        address _spender,
        uint256 _addedValue
    )
    public
    returns (bool)
    {
        allowed[msg.sender][_spender] = add(allowed[msg.sender][_spender], _addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function decreaseApproval(
        address _spender,
        uint256 _subtractedValue
    )
    public
    returns (bool)
    {
        uint256 oldValue = allowed[msg.sender][_spender];

        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } 
        else 
        {
            allowed[msg.sender][_spender] = sub(oldValue, _subtractedValue);
        }
        
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    // ============== admin 相关函数 ==================
    modifier admin_only()
    {
        require(msg.sender==admin_address);
        _;
    }

    function setAdmin( address new_admin_address ) 
    public 
    admin_only 
    returns (bool)
    {
        require(new_admin_address != address(0));
        admin_address = new_admin_address;
        return true;
    }

    // 虽然没有开启直投，但也可能转错钱的，给合约留一个提现口总是好的
    function withDraw()
    public
    admin_only
    {
        require(address(this).balance > 0);
        admin_address.transfer(address(this).balance);
    }
    // ======================================
    /// 默认函数
    function () external payable
    {
    }

    // ========== 公用函数 ===============
    // 主要就是 safemath
    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) 
    {
        if (a == 0) 
        {
            return 0;
        }

        c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) 
    {
        return a / b;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) 
    {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) 
    {
        c = a + b;
        assert(c >= a);
        return c;
    }

}