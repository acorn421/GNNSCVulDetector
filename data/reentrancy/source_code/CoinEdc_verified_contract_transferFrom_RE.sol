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
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` after balance updates but BEFORE allowance updates
 * 2. The call attempts to notify the recipient contract about the token transfer
 * 3. The allowance decrement happens AFTER the external call, creating a vulnerable window
 * 4. Used low-level call to avoid reverting on failure, ensuring function continues
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup + Initial Exploitation):**
 * - Attacker calls `transferFrom(victim, attackerContract, amount)`
 * - Balance updates occur: victim's balance decreases, attacker's balance increases
 * - External call triggers `attackerContract.onTokenReceived()`
 * - Inside the callback, attacker can call `transferFrom` again with the SAME allowance (not yet decremented)
 * - This creates inconsistent state but may hit gas limits, requiring additional transactions
 * 
 * **Transaction 2+ (Complete Exploitation):**
 * - Attacker makes additional `transferFrom` calls using the same allowance
 * - Each call can transfer more tokens because the allowance wasn't properly decremented in previous calls
 * - The vulnerability compounds across multiple transactions due to the persistent state inconsistency
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 1. **Gas Limits**: Deep reentrancy in a single transaction may hit gas limits
 * 2. **State Accumulation**: The vulnerability's impact increases with each transaction as more tokens are drained
 * 3. **Allowance Persistence**: The allowance mapping persists between transactions, allowing repeated exploitation
 * 4. **Complex Attack Patterns**: Real-world exploitation often involves multiple transactions to maximize token extraction while avoiding detection
 * 
 * **Realistic Attack Vector:**
 * An attacker could create a malicious contract that implements `onTokenReceived()` to perform additional `transferFrom` calls, effectively using the same allowance multiple times across different transactions to drain more tokens than authorized.
 */
pragma solidity ^0.4.23;

contract CoinEdc // @eachvar
{
    // 
    // 
    address public admin_address = 0x5e9b9d10247a7c5638a9bcdea4bf55981496eaa3; // @eachvar
    address public account_address = 0x5e9b9d10247a7c5638a9bcdea4bf55981496eaa3; // @eachvar 
    
    // 
    mapping(address => uint256) balances;
    
    // solidity 
    string public name = "EDC数字能源链"; // @eachvar
    string public symbol = "EDC"; // @eachvar
    uint8 public decimals = 18; // @eachvar
    uint256 initSupply = 3000000000; // @eachvar
    uint256 public totalSupply = 0; // @eachvar

    // 
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
        // Notify recipient of transfer - creates reentrancy opportunity
        if (isContract(_to)) {
            // Dynamic call, preserves the reentrancy vulnerability
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper function for contract detection (Solidity <0.5.0)
    function isContract(address _addr) internal view returns(bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }
}
