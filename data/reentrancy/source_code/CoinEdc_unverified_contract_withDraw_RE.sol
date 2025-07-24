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
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Multi-Transaction Setup Phase**: The vulnerability requires the admin to first set a malicious contract as admin_address using setAdmin() in a previous transaction.
 * 
 * 2. **External Call Before State Protection**: The function performs admin_address.transfer() before implementing any reentrancy protection mechanisms.
 * 
 * 3. **Stateful Exploitation**: The vulnerability relies on the persistent state of address(this).balance being checked fresh on each reentrant call, allowing multiple withdrawals.
 * 
 * 4. **Multi-Transaction Exploitation Sequence**:
 *    - Transaction 1: Admin calls setAdmin() to set a malicious contract as admin_address
 *    - Transaction 2: Admin calls withDraw() - the malicious contract's fallback function re-enters withDraw()
 *    - During reentrancy: Each recursive call sees the same contract balance and can drain more funds
 *    - The vulnerability requires this sequence because the admin_address must be a contract with malicious fallback
 * 
 * 5. **State Persistence**: The contract balance persists between transactions and is vulnerable to being drained through recursive calls that all see the same balance value.
 * 
 * 6. **Realistic Pattern**: This follows real-world reentrancy patterns where withdrawal functions lack proper state management and reentrancy guards, making it exploitable only when combined with a malicious admin contract setup in prior transactions.
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
        // Record the pending withdrawal before external call
        uint256 amount = address(this).balance;
        // Vulnerable: External call before state update
        // This allows reentrancy during the transfer callback
        admin_address.transfer(amount);
        // State update happens after external call - TOO LATE!
        // In a secure implementation, we would track withdrawals
        // and prevent multiple withdrawals, but this is missing
        // The vulnerability: no reentrancy protection and 
        // balance check happens fresh on each call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
