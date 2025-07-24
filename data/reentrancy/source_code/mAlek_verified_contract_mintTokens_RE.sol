/*
 * ===== SmartInject Injection Details =====
 * Function      : mintTokens
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external call to a user-controlled contract (_to) through the IMintNotification interface. This call occurs after updating the recipient's balance but before updating the total supply, creating a window for reentrancy exploitation. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **State Inconsistency Window**: The external call happens after balances[_to] is updated but before _totalSupply is updated, creating temporary state inconsistency
 * 2. **Multi-Transaction Exploitation**: An attacker can deploy a malicious contract that implements IMintNotification and:
 *    - Transaction 1: Call mintTokens() normally, which triggers the external call
 *    - During the external call, the attacker can observe that their balance has increased but total supply hasn't been updated yet
 *    - The attacker can then call other functions (like transfer()) using the newly minted tokens before the original mintTokens() call completes
 *    - Transaction 2: The attacker can leverage the temporary state inconsistency to manipulate token economics or perform unauthorized transfers
 * 
 * 3. **Accumulated State Exploitation**: Multiple calls to mintTokens() with malicious contracts can accumulate state inconsistencies, allowing attackers to:
 *    - Mint tokens and immediately transfer them before total supply is updated
 *    - Exploit the temporary balance/total supply mismatch for economic attacks
 *    - Chain multiple reentrancy calls across different transactions to amplify the effect
 * 
 * This vulnerability requires multiple transactions because the exploitable state persists between the balance update and total supply update, and the attacker needs separate transaction contexts to fully exploit the inconsistent state.
 */
pragma solidity ^0.4.11;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

interface IMintNotification {
    function onTokensMinted(address minter, uint256 amount) external;
}

contract mAlek {

    using SafeMath for uint256;

    uint public _totalSupply = 0;

    string public constant symbol = "mAlek";
    string public constant name = "mAlek Token";
    uint8 public constant decimals = 18;
    uint256 public bonus = 50;
    uint256 public price = 1000;
    uint256 public rate;

    address public owner;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function () public payable {
        createTokens();
    }

    constructor() public {
        owner = msg.sender;
    }

    function setBonus (uint256 newBonus) public {
        require (owner == msg.sender);
        bonus = newBonus;
    }

    function setPrice (uint256 newPrice) public {
        require (owner == msg.sender);
        price = newPrice;
    }

    function createTokens() public payable {
        require (msg.value > 0);
        rate = ((bonus.add(100)).mul(price));
        uint256 tokens = (msg.value.mul(rate)).div(100);
        balances[msg.sender] = balances[msg.sender].add(tokens);
        _totalSupply = _totalSupply.add(tokens);
        owner.transfer(msg.value);
    }

    function mintTokens(address _to, uint256 _value) public {
        require (owner == msg.sender);        
        balances[_to] = balances[_to].add(_value*10**18);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of minted tokens - vulnerable to reentrancy
        if (_to != address(0) && isContract(_to)) {
            IMintNotification(_to).onTokensMinted(msg.sender, _value*10**18);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _totalSupply = _totalSupply.add(_value*10**18);
        Transfer(0x0, this, _value*10**18);
        Transfer(this, _to, _value*10**18);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function totalSupply () public constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf (address _owner) public constant returns (uint256) {
        return balances[_owner];
    }

    function transfer (address _to, uint256 _value) public returns (bool success) {
        require (balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;        
    }

    function transferFrom (address _from, address _to, uint256 _value) public returns (bool success) {
        require (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve (address _spender, uint256 _value) public returns (bool success) {
        allowed [msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance (address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer (address indexed _from, address indexed _to, uint256 _value);
    event Approval (address indexed _owner, address indexed _spender, uint256 _value);
}
