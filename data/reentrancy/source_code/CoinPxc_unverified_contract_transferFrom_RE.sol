/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. Added external call to `_to` address with `onTokenReceived` callback before allowance decrement
 * 2. Moved allowance update (`allowed[_from][msg.sender] = sub(...)`) to AFTER the external call
 * 3. Added contract existence check using `_to.code.length > 0` for realism
 * 4. Added require statement for callback success to maintain function integrity
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * - **Transaction 1**: Attacker calls transferFrom, triggering the external call to malicious contract
 * - **Reentrancy Window**: During callback, allowance is not yet decremented, so attacker can call transferFrom again
 * - **Transaction 2+**: Each reentrant call exploits the same allowance value, draining more tokens than approved
 * - **State Persistence**: The allowance state persists between transactions, enabling accumulated exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **Allowance Accumulation**: Each transaction exploits the same allowance value before it's decremented
 * 2. **State Dependency**: The vulnerability depends on the persistent allowance state from previous transactions
 * 3. **Sequential Exploitation**: Attacker needs multiple calls to maximize token drainage beyond the originally approved amount
 * 4. **Cross-Transaction State**: The inconsistent state (updated balances but unchanged allowances) persists between transaction boundaries
 * 
 * **Realistic Attack Scenario:**
 * - Attacker gets approved for 100 tokens
 * - Calls transferFrom for 100 tokens, triggering callback
 * - In callback, calls transferFrom again for another 100 tokens (same allowance still shows 100)
 * - Process repeats until balances are drained, far exceeding the 100 token approval
 * - Each transaction builds on the state changes from previous transactions
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        balances[_to] = add(balances[_to], _value);
        
        // Notify recipient contract of token transfer - external call before allowance update
        if (isContract(_to)) {
            (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            require(success, "Token transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        allowed[_from][msg.sender] = sub(allowed[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
