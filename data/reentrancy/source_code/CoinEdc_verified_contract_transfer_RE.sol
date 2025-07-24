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
 * **Specific Changes Made:**
 * 
 * 1. **External Call Injection**: Added a call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before balance updates
 * 2. **Contract Detection**: Added `isContract()` helper function to only trigger external calls for contract addresses
 * 3. **Violation of CEI Pattern**: The external call now occurs before state modifications, creating a classic reentrancy vulnerability
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup (Transaction 1):**
 * - Attacker deploys malicious contract implementing `onTokenReceived` callback
 * - Attacker acquires legitimate tokens through normal means
 * - Attacker's balance: 100 tokens, Victim's balance: 1000 tokens
 * 
 * **Phase 2 - Initial Exploitation (Transaction 2):**
 * - Attacker calls `transfer(maliciousContract, 100)` 
 * - Function executes external call to `maliciousContract.onTokenReceived()`
 * - Malicious contract's callback re-enters `transfer()` multiple times before original balance update
 * - Each re-entry transfers the same 100 tokens again (since balance not yet decremented)
 * - After exploitation: Attacker's balance: 0, Malicious contract balance: 500 tokens
 * 
 * **Phase 3 - Continued Exploitation (Transaction 3+):**
 * - Attacker can repeat the process with accumulated tokens
 * - Each transaction builds upon the state from previous transactions
 * - The attack scales with the number of transactions and gas limits
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: Each successful reentrancy attack accumulates tokens in the attacker's contract, which persists between transactions
 * 2. **Progressive Exploitation**: The vulnerability becomes more profitable with each transaction as the attacker builds up a larger token balance
 * 3. **Setup Dependency**: The attack requires prior setup of the malicious contract and initial token acquisition
 * 4. **Gas Limit Constraints**: Single transaction gas limits prevent unlimited reentrancy depth, requiring multiple transactions for large-scale exploitation
 * 
 * **Realistic Vulnerability Characteristics:**
 * 
 * - The external call appears legitimate (token transfer notification)
 * - The vulnerability follows real-world patterns seen in DeFi protocols
 * - The code maintains original functionality while introducing the flaw
 * - The exploit requires sophisticated contract interaction, not just simple function calls
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call before state updates - creates reentrancy vulnerability
        if (isContract(_to)) {
            // Notify recipient contract before updating balances
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = sub(balances[msg.sender],_value);
        balances[_to] = add(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    // Helper function to check if address is a contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====账相关逻辑 =============
    
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
