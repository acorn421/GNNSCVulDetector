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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call using `_to.call()` with `onTokenReceived` callback before balance state updates
 * 2. The call occurs after balance validation but before the actual balance decrement
 * 3. Added code length check to only call contracts, making it appear as a legitimate recipient notification feature
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls transfer() to malicious contract
 * 2. **During TX1**: External call triggers malicious contract's onTokenReceived()
 * 3. **TX2 (Nested)**: Malicious contract calls transfer() again while TX1 is still executing
 * 4. **TX3+ (Nested)**: Process repeats, allowing multiple withdrawals before any balance update
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the persistent state of `balances[msg.sender]` between external calls
 * - Each nested call in the reentrancy chain represents a separate transaction context
 * - The exploit accumulates multiple transfers before any balance decrement takes effect
 * - Single-transaction exploitation is impossible due to the stateful nature of balance checks across call frames
 * 
 * **Realistic Exploitation Scenario:**
 * An attacker deploys a malicious contract that implements `onTokenReceived()` to recursively call `transfer()` back to itself multiple times, draining the sender's balance through accumulated transfers before the first balance update occurs.
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add transfer notification callback to recipient before state update
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            // External call to recipient before state changes - creates reentrancy window
            require(_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value)), "Transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
