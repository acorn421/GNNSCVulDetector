/*
 * ===== SmartInject Injection Details =====
 * Function      : withDraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking state variables and implementing a flawed withdrawal control mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added withdrawal cooldown period (1 hour between withdrawals)
 * 2. Added daily withdrawal amount tracking 
 * 3. Added withdrawal-in-progress flag
 * 4. Placed state updates before the external call (admin_address.transfer)
 * 5. Critical state cleanup happens after the external call
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Admin calls withDraw() for the first time - establishes baseline state
 * 2. **Transaction 2**: After cooldown, admin calls withDraw() again, but admin_address is a malicious contract
 * 3. **During Transaction 2**: The malicious contract's fallback function triggers reentrancy:
 *    - withdrawalInProgress was set to true but can be bypassed
 *    - dailyWithdrawnAmount is updated but state cleanup is pending
 *    - The reentrancy call can bypass the "withdrawalInProgress" check inconsistently
 * 4. **Transaction 3+**: Multiple reentrant calls exploit the state inconsistencies
 * 
 * **Why Multi-Transaction is Required:**
 * - The cooldown mechanism requires waiting between legitimate withdrawal attempts
 * - State accumulation (dailyWithdrawnAmount) builds up over multiple calls
 * - The vulnerability depends on the specific timing and state from previous transactions
 * - Single-transaction atomic exploitation is prevented by the cooldown and state tracking
 * - The malicious admin contract needs to be set up in a separate transaction before exploitation
 * 
 * **Realistic Vulnerability Pattern:**
 * This follows real-world patterns where admin functions implement safety mechanisms (cooldowns, limits) but violate the checks-effects-interactions pattern, creating windows for multi-transaction exploitation through accumulated state manipulation.
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
    
    // Additional variables for reentrancy vulnerability
    mapping(address => uint256) public lastWithdrawalTime;
    mapping(address => uint256) public dailyWithdrawnAmount;  
    uint256 public dailyWithdrawalLimit = 10 ether;
    bool public withdrawalInProgress = false;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(block.timestamp >= lastWithdrawalTime[msg.sender] + 1 hours, "Withdrawal cooldown not met");
        require(!withdrawalInProgress, "Withdrawal already in progress");
        
        uint256 currentDay = block.timestamp / 1 days;
        uint256 amount = address(this).balance;
        
        // State modifications before external call - vulnerability point
        withdrawalInProgress = true;
        dailyWithdrawnAmount[msg.sender] += amount;
        
        // External call that can trigger reentrancy
        admin_address.transfer(amount);
        
        // State updates after external call - can be bypassed through reentrancy
        lastWithdrawalTime[msg.sender] = block.timestamp;
        withdrawalInProgress = false;
        
        // Reset daily limit if new day
        if (currentDay > lastWithdrawalTime[msg.sender] / 1 days) {
            dailyWithdrawnAmount[msg.sender] = amount;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // 默认函数 (fallback)
    function () external payable {}

    // Math functions
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
