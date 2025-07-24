/*
 * ===== SmartInject Injection Details =====
 * Function      : confirmOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner before state updates. This creates a classic Checks-Effects-Interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Nature**: The vulnerability requires at least 2 transactions:
 *    - Transaction 1: `changeOwner()` to set the `newOwner` state variable
 *    - Transaction 2: `confirmOwner()` where the vulnerable external call occurs
 * 
 * 2. **State Persistence**: The `newOwner` state variable persists between transactions, enabling the vulnerability. The attacker can deploy a malicious contract, call `changeOwner()` to set it as `newOwner`, then call `confirmOwner()` to trigger the vulnerable callback.
 * 
 * 3. **Reentrancy Exploitation**: During the external call to `onOwnershipConfirmed()`, the malicious contract can:
 *    - Call `confirmOwner()` again before `owner` and `newOwner` are updated
 *    - Potentially interfere with the ownership transfer process
 *    - Access contract state in an inconsistent state where the check passed but state hasn't been updated
 * 
 * 4. **Realistic Functionality**: The added notification mechanism is realistic - many ownership transfer implementations include callbacks to notify parties of state changes.
 * 
 * The vulnerability is exploitable because the external call happens after the `require` check but before the critical state updates (`owner = newOwner; delete newOwner;`), allowing reentrancy during the window when the contract is in an inconsistent state.
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
    require(_owner != address(0));
    newOwner = _owner;
    }
    
    function confirmOwner()
    public 
    { 
    require(newOwner == msg.sender);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // VULNERABLE: External call before state updates
    // Notify the new owner about ownership confirmation
    if (isContract(newOwner)) {
        newOwner.call(
            abi.encodeWithSignature("onOwnershipConfirmed(address)", owner)
        );
        // Continue even if call fails to maintain functionality
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    owner = newOwner;
    delete newOwner;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
}