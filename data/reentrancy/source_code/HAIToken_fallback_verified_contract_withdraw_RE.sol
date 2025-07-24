/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability through the withdraw function. The vulnerability is stateful and requires multiple transactions: 1) First, an attacker must deposit ether using the deposit() function to establish a balance state, 2) Then, the attacker calls withdraw() which makes an external call before updating the state, allowing for recursive calls that can drain more ether than the attacker's balance. The vulnerability requires the persistent state in etherBalance mapping and cannot be exploited in a single transaction without prior setup.
 */
pragma solidity ^0.4.24;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

contract HAIToken {
    
    using SafeMath for uint256;
    
    string public name = "HAI";      //  token name
    
    string public symbol = "HAI";           //  token symbol
    
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    
    mapping (address => mapping (address => uint256)) public allowance;
 
    
    uint256 public totalSupply = 0;

    uint256 constant valueFounder = 10000000000000000;
    
    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public etherBalance;
    
    function deposit() public payable {
        etherBalance[msg.sender] = etherBalance[msg.sender].add(msg.value);
    }
    
    function withdraw(uint256 _amount) public {
        require(etherBalance[msg.sender] >= _amount);
        
        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(_amount)()) {
            etherBalance[msg.sender] = etherBalance[msg.sender].sub(_amount);
        }
    }
    
    function getEtherBalance(address _user) public view returns (uint256) {
        return etherBalance[_user];
    }
    // === END FALLBACK INJECTION ===

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        totalSupply = valueFounder;
        balanceOf[msg.sender] = valueFounder;
        emit Transfer(0x0, msg.sender, valueFounder);
    }
    
    function _transfer(address _from, address _to, uint256 _value) private {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
    }
    
    function transfer(address _to, uint256 _value) validAddress public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) validAddress public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
}
