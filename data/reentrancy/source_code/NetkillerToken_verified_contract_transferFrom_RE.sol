/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Added a callback mechanism that makes an external call to the recipient contract BEFORE updating the allowance state. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Exploitation**: An attacker can deploy a malicious contract as the recipient that implements ITokenReceiver.onTokenReceived()
 * 2. **State Persistence**: The allowance mapping persists between transactions, allowing the attacker to exploit the same allowance multiple times
 * 3. **Reentrancy Vector**: When the external call is made to the recipient contract, it can call back into transferFrom before the allowance is decremented
 * 4. **Sequence Dependency**: The vulnerability requires multiple calls in sequence - the first call triggers the callback, and subsequent reentrant calls exploit the unchanged allowance
 * 
 * **Exploitation Process:**
 * - Transaction 1: Attacker calls transferFrom with their malicious contract as _to
 * - During execution: The external call to onTokenReceived triggers before allowance update
 * - Reentrant calls: The malicious contract calls transferFrom again with the same (unchanged) allowance
 * - This can be repeated multiple times before the original transaction completes, draining more tokens than the allowance should permit
 * 
 * The vulnerability is realistic as token notification callbacks are common in modern ERC-20 implementations, and the placement of the external call before state updates violates the Checks-Effects-Interactions pattern.
 */
pragma solidity ^0.4.25;

/******************************************/
/*     Netkiller Standard safe token      */
/******************************************/
/* Author netkiller <netkiller@msn.com>   */
/* Home http://www.netkiller.cn           */
/* Version 2018-09-30                     */
/******************************************/

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, reverts on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    return c;
  }

  /**
  * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }

  /**
  * @dev Adds two numbers, reverts on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }

  /**
  * @dev Divides two numbers and returns the remainder (unsigned integer modulo),
  * reverts when dividing by zero.
  */
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract Ownable {
    
    address public owner;
    
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

}

interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external returns (bool);
}

contract NetkillerToken is Ownable{
    
    using SafeMath for uint256;
    
    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;
    
    mapping (address => uint256) internal balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint decimalUnits
    ) public {
        owner = msg.sender;
        name = tokenName;
        symbol = tokenSymbol; 
        decimals = decimalUnits;
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply;
    }

    function balanceOf(address _address) view public returns (uint256 balance) {
        return balances[_address];
    }
    
    function _transfer(address _from, address _to, uint256 _value) internal {
        require (_to != address(0));
        require (balances[_from] >= _value);
        require (balances[_to] + _value > balances[_to]);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient contract about incoming transfer (external call before state update)
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) view public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function airdrop(address[] _to, uint256 _value) onlyOwner public returns (bool success) {
        
        require(_value > 0 && balanceOf(msg.sender) >= _value.mul(_to.length));
        
        for (uint i=0; i<_to.length; i++) {
            _transfer(msg.sender, _to[i], _value);
        }
        return true;
    }
    
    function batchTransfer(address[] _to, uint256[] _value) onlyOwner public returns (bool success) {
        require(_to.length == _value.length);

        uint256 amount = 0;
        for(uint n=0;n<_value.length;n++){
            amount = amount.add(_value[n]);
        }
        
        require(amount > 0 && balanceOf(msg.sender) >= amount);
        
        for (uint i=0; i<_to.length; i++) {
            transfer(_to[i], _value[i]);
        }
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
