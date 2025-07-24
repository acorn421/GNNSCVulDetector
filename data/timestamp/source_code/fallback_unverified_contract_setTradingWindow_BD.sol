/*
 * ===== SmartInject Injection Details =====
 * Function      : setTradingWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. First, the owner sets a trading window with setTradingWindow(), then users can call executeTimedTransfer() only within that window. The vulnerability lies in the enableEmergencyTrading() function which allows the owner to manipulate the trading window based on block.timestamp (now), and the executeTimedTransfer() function relies on timestamp comparisons that miners can manipulate. An attacker (if they become owner through the ownership transfer mechanism) can exploit this by: 1) Setting a future trading window, 2) Calling enableEmergencyTrading() to manipulate the window timing, 3) Then calling executeTimedTransfer() at precisely manipulated timestamps. This requires multiple transactions and state persistence between calls.
 */
pragma solidity ^0.4.25;
/* TLCLUB CRYPTO-BANK THE FIRST EDITION
THE NEW ECONOMY PROJECT
CREATED 2018-10-04 BY DAO DRIVER ETHEREUM (c)*/
contract OWN
{
    address public owner;
    address internal newOwner;
    
    constructor() 
    public
    payable
    {
    owner = msg.sender;
    }
    
    modifier onlyOwner 
    {
    require(owner == msg.sender);
    _;
    }
    
    function changeOwner(address _owner)
    onlyOwner 
    public
    {
    require(_owner != 0);
    newOwner = _owner;
    }
    
    function confirmOwner()
    public 
    { 
    require(newOwner == msg.sender);
    owner = newOwner;
    delete newOwner;
    }
}
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
    return 0;
    }
    uint256 c = a*b;
    assert(c/a == b);
    return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a/b;
    return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
    }
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
    }
}
contract ERC20
{
    string public constant name     = "TLIFE";
    string public constant symbol   = "TLF";
    uint8  public constant decimals =  6;
    uint256 public totalSupply;
    
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    mapping (address => mapping(address => uint256)) public allowance;
    mapping (address => uint256) public balanceOf;
    
    function balanceOf(address who)
    public constant
    returns (uint)
    {
    return balanceOf[who];
    }
    
    function approve(address _spender, uint _value)
    public
    {
    allowance[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    }
    
    function allowance(address _owner, address _spender) 
    public constant 
    returns (uint remaining) 
    {
    return allowance[_owner][_spender];
    }
    
    modifier onlyPayloadSize(uint size) 
    {
    require(msg.data.length >= size + 4);
    _;
    }
}

contract TLIFE is OWN, ERC20
{
    using SafeMath for uint256;
    uint256 internal Bank = 0;
    uint256 public Price = 800000000;
    uint256 internal constant Minn = 10000000000000000;
    uint256 internal constant Maxx = 10000000000000000000;
    address internal constant ethdriver = 0x61585C21E0C0c5875EaB1bc707476BD0a28f157b;
   
    function() 
    payable 
    public
        {
        require(msg.value>0);
        require(msg.value >= Minn);
        require(msg.value <= Maxx);
        mintTokens(msg.sender, msg.value);
        }
        
    function mintTokens(address _who, uint256 _value) 
    internal 
        {
        uint256 tokens = _value / (Price*10/8); //sale
        require(tokens > 0); 
        require(balanceOf[_who] + tokens > balanceOf[_who]);
        totalSupply += tokens; //mint
        balanceOf[_who] += tokens; //sale
        uint256 perc = _value.div(100);
        Bank += perc.mul(85);  //reserve
        Price = Bank.div(totalSupply); //pump
        uint256 minus = _value % (Price*10/8); //change
        require(minus > 0);
        emit Transfer(this, _who, tokens);
        _value=0; tokens=0;
        owner.transfer(perc.mul(5)); //owners
        ethdriver.transfer(perc.mul(5)); //systems
        _who.transfer(minus); minus=0;
        }
        
    function transfer (address _to, uint _value) 
    public onlyPayloadSize(2 * 32) 
    returns (bool success)
        {
        require(balanceOf[msg.sender] >= _value);
        if(_to != address(this)) //standart
        {
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        }
        else //tokens to contract
        {
        balanceOf[msg.sender] -= _value;
        uint256 change = _value.mul(Price);
        require(address(this).balance >= change);
		
		if(totalSupply > _value)
		{
        uint256 plus = (address(this).balance - Bank).div(totalSupply);    
        Bank -= change; totalSupply -= _value;
        Bank += (plus.mul(_value));  //reserve
        Price = Bank.div(totalSupply); //pump
        emit Transfer(msg.sender, _to, _value);
        }
        if(totalSupply == _value)
        {
        Price = address(this).balance/totalSupply;
        Price = (Price.mul(101)).div(100); //pump
        totalSupply=0; Bank=0;
        emit Transfer(msg.sender, _to, _value);
        owner.transfer(address(this).balance - change);
        }
        msg.sender.transfer(change);
        }
        return true;
        }
    
    function transferFrom(address _from, address _to, uint _value) 
    public onlyPayloadSize(3 * 32)
    returns (bool success)
        {
        require(balanceOf[_from] >= _value);
        require(allowance[_from][msg.sender] >= _value);
        if(_to != address(this)) //standart
        {
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        }
        else //sale
        {
        balanceOf[_from] -= _value;
        uint256 change = _value.mul(Price);
        require(address(this).balance >= change);
        if(totalSupply > _value)
        {
        uint256 plus = (address(this).balance - Bank).div(totalSupply);   
        Bank -= change;
        totalSupply -= _value;
        Bank += (plus.mul(_value)); //reserve
        Price = Bank.div(totalSupply); //pump
        emit Transfer(_from, _to, _value);
        allowance[_from][msg.sender] -= _value;
        }
        if(totalSupply == _value)
        {
        Price = address(this).balance/totalSupply;
        Price = (Price.mul(101)).div(100); //pump
        totalSupply=0; Bank=0; 
        emit Transfer(_from, _to, _value);
        allowance[_from][msg.sender] -= _value;
        owner.transfer(address(this).balance - change);
        }
        _from.transfer(change);
        }
        return true;
        }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public tradingWindowStart;
    uint256 public tradingWindowEnd;
    bool public tradingWindowActive = false;
    
    function setTradingWindow(uint256 _startTime, uint256 _endTime) 
    public 
    onlyOwner 
    {
        require(_startTime < _endTime);
        require(_startTime >= now);
        tradingWindowStart = _startTime;
        tradingWindowEnd = _endTime;
        tradingWindowActive = true;
    }
    
    function enableEmergencyTrading() 
    public 
    onlyOwner 
    {
        require(tradingWindowActive);
        require(now >= tradingWindowStart - 300); // 5 minutes before window
        tradingWindowStart = now;
        tradingWindowEnd = now + 3600; // 1 hour emergency window
    }
    
    function executeTimedTransfer(address _to, uint256 _value) 
    public 
    returns (bool success) 
    {
        require(tradingWindowActive);
        require(now >= tradingWindowStart);
        require(now <= tradingWindowEnd);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        
        return true;
    }
    // === END FALLBACK INJECTION ===

}