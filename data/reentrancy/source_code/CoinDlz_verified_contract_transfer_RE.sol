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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism between balance deduction and credit. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenReceived` callback after sender balance deduction
 * 2. The callback occurs before the recipient's balance is credited, creating a state inconsistency window
 * 3. Added a contract code length check to only call contracts, not EOAs
 * 4. Execution continues regardless of callback success to maintain functionality
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls transfer() to a malicious contract
 * 2. **During TX1**: The malicious contract's onTokenReceived() callback is triggered
 * 3. **Reentrant Calls**: The callback can make additional transfer() calls while the original transfer is still in progress
 * 4. **State Window**: Between multiple transactions, the attacker can exploit the inconsistent state where sender balance is reduced but recipient balance isn't yet credited
 * 5. **Accumulated Effect**: Multiple reentrant calls can drain more tokens than the attacker originally had
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the state window between balance deduction and credit
 * - Each reentrant call operates on the updated sender balance from previous calls
 * - The attacker needs to accumulate multiple transfer operations to drain significant funds
 * - The exploit requires building up state across multiple function invocations to be effective
 * 
 * **Realistic Implementation:**
 * - Token callback mechanisms are common in modern token standards (ERC777, ERC1363)
 * - The code appears to be a legitimate notification feature for smart contracts
 * - The vulnerability is subtle and could easily be missed in code reviews
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
    mapping(address => mapping(address => uint256)) allowed;
    
    // solidity 会自动为 public 变量添加方法，有了下边这些变量，就能获得代币的基本信息了
    string public name = "digitalcash"; // @eachvar
    string public symbol = "DLZ"; // @eachvar
    uint8 public decimals = 8; // @eachvar
    uint256 initSupply = 42000000; // @eachvar
    uint256 public totalSupply = 0; // @eachvar

    // 生成代币，并转入到 account_address 地址
    constructor() 
    public
    payable 
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
    event Approval(
        address indexed owner,
        address indexed spender,
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about incoming tokens - potential reentrancy point
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        balances[_to] = add(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

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
    /// 默认函数
    function () external payable
    {
        // fallback, receive ether
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
