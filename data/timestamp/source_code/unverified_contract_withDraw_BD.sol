/*
 * ===== SmartInject Injection Details =====
 * Function      : withDraw
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a sophisticated timestamp dependence vulnerability through a time-based withdrawal limit system. The vulnerability involves multiple state variables (lastWithdrawTime, accumulatedWithdrawAmount, totalWithdrawnAmount, withdrawalCooldown, dailyWithdrawLimit) that persist across transactions. The exploit requires multiple transactions over time where an attacker (potentially colluding with miners) can manipulate block.timestamp to:
 * 
 * 1. **Transaction 1**: Make initial withdrawal, setting lastWithdrawTime
 * 2. **Transaction 2**: Manipulate timestamp to appear as if more time has passed, increasing timeBasedAllowance
 * 3. **Transaction 3**: Repeat manipulation to drain more funds incrementally
 * 4. **Transaction 4**: After multiple rounds, reset cooldown period and drain remaining balance
 * 
 * The vulnerability is multi-transaction because:
 * - State variables persist between calls and accumulate withdrawal permissions
 * - Each transaction builds upon previous timestamp states
 * - The exploit requires a sequence of strategically timed transactions
 * - Single transaction exploitation is impossible due to state dependencies
 * 
 * The vulnerability is realistic as it implements a common security pattern (withdrawal limits) but relies on block.timestamp for critical calculations, making it exploitable through miner timestamp manipulation or careful timing attacks across multiple blocks.
 */
pragma solidity ^0.4.23;

contract CoinPxc // @eachvar
{
    // ======== 初始化代币相关逻辑 ==============
    // 地址信息
    address public admin_address = 0xc4D506F128EB82F00d0dA3e6Aab14f27feB925C1; // @eachvar
    address public account_address = 0xc4D506F128EB82F00d0dA3e6Aab14f27feB925C1; // @eachvar 初始化后转入代币的地址
    
    // 定义账户余额
    mapping(address => uint256) balances;
    
    // solidity 会自动为 public 变量添加方法，有了下边这些变量，就能获得代币的基本信息了
    string public name = "貔貅金币"; // @eachvar
    string public symbol = "PXC"; // @eachvar
    uint8 public decimals = 18; // @eachvar
    uint256 initSupply = 3500000000; // @eachvar
    uint256 public totalSupply = 0; // @eachvar

    // ===== vulnerable withdraw state =====
    uint256 public lastWithdrawTime = 0;
    uint256 public withdrawalCooldown = 86400; // 1 day
    uint256 public accumulatedWithdrawAmount = 0;
    uint256 public dailyWithdrawLimit = 100 ether; // example value
    uint256 public totalWithdrawnAmount = 0;

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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function vulnerableWithDraw() public admin_only {
        require(address(this).balance > 0);
        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastWithdraw = currentTime - lastWithdrawTime;
        uint256 maxWithdrawAmount;
        if (timeSinceLastWithdraw >= withdrawalCooldown) {
            accumulatedWithdrawAmount = 0;
            maxWithdrawAmount = address(this).balance;
        } else {
            uint256 timeBasedAllowance = mul(timeSinceLastWithdraw, dailyWithdrawLimit) / 86400; // 24 hours
            maxWithdrawAmount = add(timeBasedAllowance, accumulatedWithdrawAmount);
            if (maxWithdrawAmount > address(this).balance) {
                maxWithdrawAmount = address(this).balance;
            }
        }
        require(maxWithdrawAmount > 0, "No withdrawal amount available yet");
        lastWithdrawTime = currentTime;
        accumulatedWithdrawAmount = maxWithdrawAmount;
        totalWithdrawnAmount = add(totalWithdrawnAmount, maxWithdrawAmount);
        admin_address.transfer(maxWithdrawAmount);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    // fallback function
    function () external payable {}

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
