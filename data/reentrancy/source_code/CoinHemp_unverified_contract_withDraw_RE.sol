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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal limits and cooldown periods that are tracked in persistent state variables. The vulnerability occurs because the external call (admin_address.transfer()) happens before the state update (lastWithdrawTime[msg.sender] = block.timestamp), allowing an attacker to re-enter and bypass the cooldown mechanism across multiple transactions.
 * 
 * **Required State Variables (to be added to contract):**
 * - mapping(address => uint256) public lastWithdrawTime;
 * - uint256 public withdrawalCooldown = 1 days;
 * - uint256 public maxWithdrawal = 10 ether;
 * 
 * **Specific Changes Made:**
 * 1. Added cooldown check using lastWithdrawTime mapping and withdrawalCooldown variable
 * 2. Implemented maximum withdrawal limit using maxWithdrawal variable
 * 3. Positioned external call (transfer) BEFORE state update (lastWithdrawTime assignment)
 * 4. This creates a classic reentrancy vulnerability where state is modified after external interaction
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Admin calls withDraw() first time, passes cooldown check, initiates transfer
 * 2. **Reentrancy**: If admin_address is a malicious contract, it can call withDraw() again during the transfer callback
 * 3. **Transaction 2+**: Subsequent reentrant calls bypass the cooldown check because lastWithdrawTime hasn't been updated yet
 * 4. **State Accumulation**: Each successful reentrant call extracts up to maxWithdrawal amount before finally updating the timestamp
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to control the admin_address (make it a malicious contract)
 * - The malicious contract must implement a fallback/receive function that calls back to withDraw()
 * - Multiple reentrant calls are needed to drain more than the maxWithdrawal limit
 * - The cooldown state persists between transactions, making this a stateful vulnerability
 * - Cannot be exploited in a single transaction without the callback mechanism
 * 
 * **Realistic Integration:**
 * This injection is highly realistic because:
 * - Withdrawal limits and cooldowns are common security measures
 * - The pattern of checking conditions before external calls is typical
 * - The state management approach mirrors real-world admin function implementations
 * - The vulnerability follows classic reentrancy patterns seen in production contracts
 */
pragma solidity ^0.4.23;

contract CoinHemp // @eachvar
{
    // ======== 初始化代币相关逻辑 ==============
    // 地址信息
    address public admin_address = 0xE00ebe6ADd57A2cf8eFBc77E046c7008f3087bC2; // @eachvar
    address public account_address = 0xE00ebe6ADd57A2cf8eFBc77E046c7008f3087bC2; // @eachvar 初始化后转入代币的地址
    
    // 定义账户余额
    mapping(address => uint256) balances;
    
    // solidity 会自动为 public 变量添加方法，有了下边这些变量，就能获得代币的基本信息了
    string public name = "hemp"; // @eachvar
    string public symbol = "HEMP"; // @eachvar
    uint8 public decimals = 18; // @eachvar
    uint256 initSupply = 400000000; // @eachvar
    uint256 public totalSupply = 0; // @eachvar

    // For vulnerable withdraw function
    mapping(address => uint256) public lastWithdrawTime;
    uint256 public withdrawalCooldown = 1 days;
    uint256 public maxWithdrawal = 1 ether;

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
        admin_address.transfer(address(this).balance);
    }
    // ======================================
    // 默认函数 (fallback)
    function () external payable {}

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function vulnerableWithdraw() public admin_only {
        require(address(this).balance > 0);
        require(block.timestamp >= lastWithdrawTime[msg.sender] + withdrawalCooldown);
        uint256 withdrawAmount = address(this).balance > maxWithdrawal ? maxWithdrawal : address(this).balance;
        admin_address.transfer(withdrawAmount);
        // State update after external call - can be bypassed via reentrancy
        lastWithdrawTime[msg.sender] = block.timestamp;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // ============= Safe Math Functions =============
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