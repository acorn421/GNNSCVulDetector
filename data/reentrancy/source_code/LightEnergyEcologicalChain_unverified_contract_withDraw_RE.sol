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
 * 1. **Added state tracking**: Introduced `pendingWithdrawals[admin_address]` to track withdrawal amounts between transactions
 * 2. **Replaced transfer with call**: Changed from `.transfer()` to `.call.value()` which provides full gas and enables reentrancy
 * 3. **State-dependent logic**: The function now depends on `pendingWithdrawals` state that persists between transactions
 * 4. **Vulnerable state management**: State clearing happens after the external call, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Admin calls `withDraw()` for the first time
 * - `pendingWithdrawals[admin_address]` is set to current balance (e.g., 100 ETH)
 * - External call triggers reentrancy to malicious admin contract
 * 
 * **Reentrant Call Chain:**
 * - During the external call, the malicious admin contract calls `withDraw()` again
 * - Since `pendingWithdrawals[admin_address]` is already set from Transaction 1, the condition `if (pendingWithdrawals[admin_address] == 0)` is false
 * - The function proceeds with the same withdrawal amount (100 ETH)
 * - This can be repeated multiple times during the same transaction
 * 
 * **Transaction 2 (State Persistence):**
 * - If the contract receives new funds between transactions
 * - The `pendingWithdrawals` state persists from previous transactions
 * - Subsequent calls can exploit the stale state to withdraw more than intended
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Accumulation**: The `pendingWithdrawals` mapping maintains state between transactions
 * 2. **Cross-Transaction Exploitation**: The vulnerability requires the state to be set in one transaction and exploited in subsequent calls
 * 3. **Realistic Business Logic**: The withdrawal tracking serves a legitimate auditing purpose, making the vulnerability subtle and realistic
 * 
 * The vulnerability is particularly dangerous because it combines immediate reentrancy with persistent state manipulation, allowing both single-transaction and multi-transaction exploitation patterns.
 */
pragma solidity ^0.4.23;

contract LightEnergyEcologicalChain // @HD.ChainFull.Co.Ltd
{

    address public admin_address = 0x5d9CC08eb47aE51069ED64BFAfBcF3a8e531f881;
    address public account_address = 0x5d9CC08eb47aE51069ED64BFAfBcF3a8e531f881;
    mapping(address => uint256) balances;
    string public name = "Light Energy Ecological Chain";
    string public symbol = "LEE";
    uint8 public decimals = 18;
    uint256 initSupply = 570000000;
    uint256 public totalSupply = 0;

    // FIX: Declare pendingWithdrawals mapping
    mapping(address => uint256) public pendingWithdrawals;

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

    function withDraw()
    public
    admin_only
    {
        require(address(this).balance > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track withdrawal requests for auditing purposes
        if (pendingWithdrawals[admin_address] == 0) {
            pendingWithdrawals[admin_address] = address(this).balance;
        }
        // Use call instead of transfer for flexibility and gas efficiency
        (bool success, ) = admin_address.call.value(pendingWithdrawals[admin_address])("");
        require(success, "Withdrawal failed");
        // Clear pending withdrawal after successful transfer
        pendingWithdrawals[admin_address] = 0;
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
