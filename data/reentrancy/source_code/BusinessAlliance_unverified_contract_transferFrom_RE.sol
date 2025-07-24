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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address between the sender's balance deduction and the allowance update. This creates a critical window where the contract state is inconsistent and can be exploited across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after the sender's balance is deducted but before the allowance is updated
 * 2. The external call is conditionally executed only if the recipient is a contract (has code)
 * 3. The call continues execution regardless of success to maintain backward compatibility
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract and gets approval for a large amount of tokens from a victim
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls transferFrom, which triggers the external call to their malicious contract
 * 3. **During the external call**: The malicious contract's `onTokenReceived` function is executed while the contract state is inconsistent (sender's balance reduced, but allowance not yet updated)
 * 4. **Reentrant Calls**: The malicious contract can make additional transferFrom calls using the same allowance that hasn't been decremented yet
 * 5. **State Accumulation**: Each reentrant call further reduces the victim's balance while the allowance remains unchanged until the original call completes
 * 
 * **Why Multiple Transactions Are Required:**
 * - **Transaction 1**: Initial approval setup must happen in a separate transaction to establish the allowance
 * - **Transaction 2**: The actual attack transaction where reentrancy occurs
 * - **Persistent State**: The allowance state persists between transactions, creating the foundation for the vulnerability
 * - **Cross-Transaction Dependencies**: The attack depends on the persistent allowance state established in previous transactions
 * 
 * **Stateful Nature:**
 * - The vulnerability exploits the persistent `allowed[_from][msg.sender]` mapping that survives between transactions
 * - The inconsistent state window (balance updated but allowance not yet decremented) allows multiple withdrawals using the same allowance
 * - The attack accumulates effects across multiple reentrant calls within the same transaction, but depends on allowance state from previous transactions
 * 
 * This vulnerability is realistic because recipient notification patterns are common in advanced token implementations, and the external call placement creates a genuine security flaw that requires multiple transactions to set up and exploit.
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient - potential reentrancy point
        // This allows the recipient to be notified of incoming transfer
        if (isContract(_to)) {
            (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of success to maintain backward compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        balances[_to] = add(balances[_to], _value);
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
        admin_address.transfer(address(this).balance);
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