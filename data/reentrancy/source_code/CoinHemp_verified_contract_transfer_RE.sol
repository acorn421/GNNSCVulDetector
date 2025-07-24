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
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **External Call Injection**: Added an external call to the recipient address (`_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))`) between the sender's balance deduction and recipient's balance addition.
 * 
 * 2. **Reentrancy Window Creation**: The external call creates a vulnerability window where:
 *    - Sender's balance is already reduced
 *    - Recipient's balance is not yet increased
 *    - The recipient contract can reenter the transfer function
 * 
 * 3. **Realistic Implementation**: The external call is disguised as a "transfer notification" mechanism, which is a common pattern in token contracts for notifying recipients of incoming transfers.
 * 
 * **MULTI-TRANSACTION EXPLOITATION PATH:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - During the external call, the malicious contract can:
 *   - Observe that sender's balance is reduced but recipient's balance not yet increased
 *   - Set up state for future exploitation
 *   - Cannot immediately exploit due to gas limits and call stack depth
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transfer()` again, this time with carefully crafted parameters
 * - The malicious contract's `onTokenReceived` is called again
 * - Now the attacker can exploit the accumulated state inconsistencies:
 *   - Previous transaction left the contract in an inconsistent state
 *   - Balance mappings have been manipulated across multiple calls
 *   - The attacker can drain tokens by exploiting the timing between balance updates
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Attacker continues to call `transfer()` multiple times
 * - Each call creates new inconsistent states that can be exploited
 * - The vulnerability compounds across multiple transactions
 * 
 * **WHY MULTI-TRANSACTION EXPLOITATION IS REQUIRED:**
 * 
 * 1. **State Accumulation**: Each transaction leaves the contract in a partially updated state that can be exploited in subsequent transactions.
 * 
 * 2. **Gas Limitations**: Deep reentrancy within a single transaction is limited by gas costs and call stack depth, requiring multiple transactions to fully exploit.
 * 
 * 3. **Stateful Conditions**: The vulnerability depends on the accumulated effects of multiple balance updates across different transactions.
 * 
 * 4. **Timing Dependencies**: The exploit requires specific timing between balance deductions and additions that can only be achieved through multiple coordinated transactions.
 * 
 * 5. **Compound Effects**: Each successful exploitation in one transaction creates favorable conditions for the next transaction, requiring a sequence of calls to maximize the attack.
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that requires an attacker to execute multiple coordinated transactions to fully exploit the flaw.
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
    
    // 授权额度
    mapping(address => mapping(address => uint256)) allowed;
    
    // solidity 会自动为 public 变量添加方法，有了下边这些变量，就能获得代币的基本信息了
    string public name = "hemp"; // @eachvar
    string public symbol = "HEMP"; // @eachvar
    uint8 public decimals = 18; // @eachvar
    uint256 initSupply = 400000000; // @eachvar
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
        // Added external call to recipient for transfer notification
        // This creates a reentrancy window before recipient balance is updated
        if (isContract(_to)) {
            // In 0.4.x do not check return value for .call, keep compat
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue even if call fails - for compatibility
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

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
