/*
 * ===== SmartInject Injection Details =====
 * Function      : depositForInvestment
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability in investment system. An attacker must first deposit funds via depositForInvestment(), then exploit the reentrancy bug in withdrawInvestment() to drain more than their investment. The vulnerability requires state persistence across multiple transactions - the investment balance persists from the deposit transaction and can be exploited in the withdrawal transaction through recursive calls.
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


    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Investment deposit tracking
    mapping(address => uint256) public investments;
    mapping(address => bool) public investmentWithdrawing;
    
    event InvestmentDeposit(address indexed investor, uint256 amount);
    event InvestmentWithdrawal(address indexed investor, uint256 amount);
    
    function depositForInvestment() 
    public 
    payable 
    {
        require(msg.value > 0, "Investment amount must be greater than 0");
        investments[msg.sender] = add(investments[msg.sender], msg.value);
        emit InvestmentDeposit(msg.sender, msg.value);
    }
    
    function withdrawInvestment() 
    public 
    {
        require(investments[msg.sender] > 0, "No investment to withdraw");
        require(!investmentWithdrawing[msg.sender], "Already withdrawing");
        
        uint256 amount = investments[msg.sender];
        investmentWithdrawing[msg.sender] = true;
        
        // Vulnerable to reentrancy: external call before state update
        msg.sender.call.value(amount)("");
        
        // State update after external call - can be bypassed by reentrancy
        investments[msg.sender] = 0;
        investmentWithdrawing[msg.sender] = false;
        
        emit InvestmentWithdrawal(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

}