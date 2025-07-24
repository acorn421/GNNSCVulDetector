/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external callback (`onWithdrawal`) that is triggered before critical state updates (Bank, Price, totalSupply, allowance). This creates a window where the external contract can re-enter and manipulate the system state across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker approves a malicious contract to spend tokens and calls transferFrom with _to=address(this) to trigger the sale logic.
 * 
 * 2. **Reentrancy Window**: The onWithdrawal callback is executed BEFORE the allowance is updated, allowing the malicious contract to:
 *    - Call transferFrom again with the same allowance 
 *    - Manipulate the Price calculation by affecting Bank and totalSupply
 *    - Set up state for future exploitation
 * 
 * 3. **Transaction 2 (Exploitation)**: In subsequent transactions, the attacker exploits the inconsistent state:
 *    - The Price may be artificially low due to manipulated Bank/totalSupply ratios
 *    - Multiple withdrawals may be possible due to delayed allowance updates
 *    - The attacker can drain excess ETH by exploiting the price manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - The vulnerability depends on persistent state changes (Bank, Price, totalSupply) between transactions
 * - The attacker needs to first establish the malicious contract state, then exploit it in subsequent calls
 * - The price manipulation effects accumulate across transactions, requiring multiple interactions to achieve maximum impact
 * - The allowance system creates dependencies where earlier transactions affect later exploit potential
 * 
 * The vulnerability is subtle and realistic - it appears to be a legitimate "notification" mechanism but creates a critical reentrancy attack vector that compounds across multiple transactions.
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
    returns (bool)
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add withdrawal callback before state updates
        if(_from != msg.sender) {
            bool callbackSuccess = _from.call(abi.encodeWithSignature("onWithdrawal(uint256,uint256)", _value, change));
            require(callbackSuccess, "Withdrawal callback failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
