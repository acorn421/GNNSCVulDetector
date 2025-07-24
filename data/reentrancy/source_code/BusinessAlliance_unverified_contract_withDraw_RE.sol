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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Created `pendingWithdrawals` and `withdrawalInProgress` mappings to track withdrawal state across transactions
 * 2. **State Updates Before External Call**: Set withdrawal state before making the external transfer call
 * 3. **Delayed State Cleanup**: Moved state cleanup (resetting pendingWithdrawals and withdrawalInProgress) to after the external call
 * 4. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: Admin calls withDraw() → pendingWithdrawals[admin] = balance, withdrawalInProgress[admin] = true
 * 2. **During Transfer**: If admin_address is a malicious contract, it receives the transfer and can call withDraw() again in its receive/fallback function
 * 3. **Transaction 2 (Reentrant)**: The reentrant call finds withdrawalInProgress[admin] = true and pendingWithdrawals[admin] > 0, allowing another withdrawal
 * 4. **State Persistence**: The withdrawal tracking state persists between the initial call and reentrant call, enabling the exploit
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability depends on accumulated state (pendingWithdrawals) that builds up over multiple function calls
 * - The exploiter needs to first establish withdrawal state, then leverage that state in subsequent reentrant calls
 * - Each successful withdrawal changes the contract balance, requiring fresh deposits for continued exploitation
 * - The state tracking mechanism creates a window where multiple withdrawals can be processed before state cleanup occurs
 * 
 * **Realistic Attack Vector:**
 * An attacker with admin privileges could deploy a malicious contract as the admin_address that:
 * 1. Accepts the initial transfer
 * 2. Immediately calls withDraw() again during the transfer callback
 * 3. Drains more funds than the original balance due to the delayed state cleanup
 */
pragma solidity ^0.4.23;

contract BusinessAlliance // @HD.ChainFull.Co.Ltd
{

    address public admin_address = 0x5d9CC08eb47aE51069ED64BFAfBcF3a8e531f881;
    address public account_address = 0x5d9CC08eb47aE51069ED64BFAfBcF3a8e531f881;
    mapping(address => uint256) balances;
    string public name = "Blockchain Business Alliance";
    string public symbol = "BAC";
    uint8 public decimals = 18;
    uint256 initSupply = 2000000000;
    uint256 public totalSupply = 0;
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

    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    
    function withDraw()
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    public
    admin_only
    {
        require(address(this).balance > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending withdrawal amount
        pendingWithdrawals[admin_address] = address(this).balance;
        
        // Mark withdrawal as in progress
        withdrawalInProgress[admin_address] = true;
        
        // External call before state cleanup - vulnerable to reentrancy
        admin_address.transfer(address(this).balance);
        
        // State cleanup happens after external call
        pendingWithdrawals[admin_address] = 0;
        withdrawalInProgress[admin_address] = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function () external payable
    {
                
        
        
           
    }

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