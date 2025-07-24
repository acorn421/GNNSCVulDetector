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
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending Transfer State**: Introduced `pendingTransfers[msg.sender][_to]` mapping to track transfers in progress, creating persistent state between transactions.
 * 
 * 2. **External Call Placement**: Added an external call to `_to.call()` after sender balance is reduced but before receiver balance is updated, creating a vulnerable window.
 * 
 * 3. **State Inconsistency Window**: The external call occurs when:
 *    - Sender balance is already reduced
 *    - Receiver balance is not yet updated
 *    - Pending transfer amount is recorded
 *    - This creates an exploitable intermediate state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Attacker calls `transfer()` to a malicious contract
 * - Sender balance reduced immediately
 * - `pendingTransfers` records the transfer amount
 * - External call triggers the malicious contract's `onTokenReceived()`
 * - During reentrancy, the malicious contract can call `transfer()` again
 * - The second call sees the reduced sender balance but can exploit the pending state
 * 
 * **Transaction 2**: Attacker exploits the accumulated pending transfers
 * - Multiple pending transfers can be accumulated from Transaction 1's reentrancy
 * - The attacker can manipulate the order of operations
 * - State inconsistencies persist between transactions via `pendingTransfers`
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction reentrancy would revert due to insufficient balance after first deduction
 * - The `pendingTransfers` state persists between transactions, enabling complex multi-step exploits
 * - Attacker needs separate transactions to build up pending state and then exploit it
 * - The vulnerability becomes more powerful with accumulated state across multiple calls
 * 
 * **Realistic Implementation:**
 * - The external call appears as a legitimate "transfer notification" feature
 * - The `pendingTransfers` tracking seems like proper accounting
 * - The vulnerability is subtle and could easily be missed in code review
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
    
    // 新增：授权 mapping 以及 pendingTransfers mapping
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => mapping(address => uint256)) pendingTransfers;

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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store pending transfer for multi-transaction processing
        pendingTransfers[msg.sender][_to] = add(pendingTransfers[msg.sender][_to], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = sub(balances[msg.sender],_value);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify receiver before state finalization
        // This enables reentrancy during the intermediate state
        if (_to != msg.sender && _to != address(0) && isContract(_to)) {
            // Call receiver's onTokenReceived function if it exists
            /* solhint-disable-next-line avoid-call-value */
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result
        }

        // Complete the transfer after external call
        balances[_to] = add(balances[_to], _value);
        
        // Clear pending transfer only after successful completion
        pendingTransfers[msg.sender][_to] = sub(pendingTransfers[msg.sender][_to], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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

}
