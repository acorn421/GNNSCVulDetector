/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * STATEFUL, MULTI-TRANSACTION Reentrancy Vulnerability:
 * 
 * **Specific Changes Made:**
 * 1. **Moved External Calls Before State Updates**: The critical `msg.sender.transfer(change)` calls are now executed BEFORE the state variables (`Bank`, `totalSupply`, `Price`) are updated in both conditional branches.
 * 2. **Removed Final External Call**: The external call that was at the end of the function (after all state updates) has been moved up, creating a classic reentrancy vulnerability pattern.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with a fallback function
 * - Attacker calls `transfer()` to send tokens to the contract address
 * - During the `msg.sender.transfer(change)` call, the attacker's contract receives control
 * - At this point, state variables are still in their original state (Bank, totalSupply, Price unchanged)
 * 
 * **Transaction 2 (Exploitation):**
 * - While still in the fallback function from Transaction 1, the attacker calls `transfer()` again
 * - Since state hasn't been updated yet, the attacker can:
 *   - Use the old `Price` value to calculate `change` (getting more ETH than deserved)
 *   - Exploit the fact that `Bank` and `totalSupply` haven't been decremented yet
 *   - Potentially drain more ETH than their token balance should allow
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability exploits the fact that state variables persist between the initial call and the reentrant call
 * 2. **Timing Dependency**: The attacker needs the external call to happen while state is in an intermediate, inconsistent state
 * 3. **Accumulated Effect**: Each reentrant call compounds the effect, as the state calculations are based on stale values
 * 4. **Cross-Call State Manipulation**: The attacker leverages state that was set up in previous transactions/calls to maximize the exploit
 * 
 * **Realistic Exploitation:**
 * - Attacker creates a contract that implements a fallback function
 * - Fallback function calls `transfer()` again during the ETH transfer
 * - Since `Bank`, `totalSupply`, and `Price` haven't been updated yet, the attacker can exploit inconsistent state
 * - Multiple reentrant calls can drain the contract's ETH reserves based on stale price calculations
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: Move external call BEFORE state updates
        msg.sender.transfer(change);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Bank -= change; totalSupply -= _value;
        Bank += (plus.mul(_value));  //reserve
        Price = Bank.div(totalSupply); //pump
        emit Transfer(msg.sender, _to, _value);
        }
        if(totalSupply == _value)
        {
        Price = address(this).balance/totalSupply;
        Price = (Price.mul(101)).div(100); //pump
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: Move external call BEFORE state updates
        msg.sender.transfer(change);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply=0; Bank=0;
        emit Transfer(msg.sender, _to, _value);
        owner.transfer(address(this).balance - change);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
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
}