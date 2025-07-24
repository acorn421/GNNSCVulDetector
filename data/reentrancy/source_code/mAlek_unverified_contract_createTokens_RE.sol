/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced transfer() with send()**: Changed from `owner.transfer(msg.value)` to `if (owner.send(msg.value))` to enable reentrancy since send() provides a gas stipend that can be used for external calls.
 * 
 * 2. **Moved state updates after external call**: The critical state modifications (`balances[msg.sender]` and `_totalSupply` updates) now occur after the external call, violating the checks-effects-interactions pattern.
 * 
 * 3. **Added conditional state updates**: State changes only happen if the send() succeeds, but the reentrancy can occur during the send() execution.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract and somehow becomes the owner (or influences the owner to be a malicious contract).
 * 
 * **Transaction 2 (Initial Call)**: Attacker calls createTokens() with ETH:
 * - Function calculates tokens based on msg.value
 * - Calls owner.send(msg.value) 
 * - Malicious owner contract's fallback function is triggered
 * - During fallback, owner contract calls createTokens() again with same msg.value
 * - This creates a reentrancy loop where tokens are calculated and minted multiple times
 * - Each reentrant call increases the attacker's balance and total supply
 * 
 * **Transaction 3+ (Continued Exploitation)**: Attacker can repeat the process in subsequent transactions, accumulating tokens while the contract's state becomes increasingly inconsistent.
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability requires the owner to be a malicious contract (setup transaction)
 * - The exploitation happens through recursive calls within a single transaction, but the setup and repeated exploitation across multiple transactions creates a stateful vulnerability
 * - Each transaction builds upon the previous state, allowing the attacker to accumulate tokens over time
 * - The contract's state (balances, totalSupply) persists between transactions, enabling continued exploitation
 * 
 * The vulnerability is subtle and realistic as it maintains the original function's intent while introducing a classic reentrancy pattern that requires multiple interactions to fully exploit.
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

    function () payable {
        createTokens();
    }

    function mAlek () {
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

    function createTokens() payable {
        require (msg.value > 0);
        rate = ((bonus.add(100)).mul(price));
        uint256 tokens = (msg.value.mul(rate)).div(100);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call moved before state updates - vulnerable to reentrancy
        if (owner.send(msg.value)) {
            // State updates occur after external call, allowing reentrancy exploitation
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function mintTokens(address _to, uint256 _value) {
        require (owner == msg.sender);        
        balances[_to] = balances[_to].add(_value*10**18);
        _totalSupply = _totalSupply.add(_value*10**18);
        Transfer(0x0, this, _value*10**18);
        Transfer(this, _to, _value*10**18);
    }

    function totalSupply () constant returns (uint256 totalSupply) {
        return _totalSupply;
    }

    function balanceOf (address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function transfer (address _to, uint256 _value) returns (bool success) {
        require (balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;        
    }

    function transferFrom (address _from, address _to, uint256 _value) returns (bool success) {
        require (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve (address _spender, uint256 _value) returns (bool success) {
        allowed [msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance (address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer (address indexed _from, address indexed _to, uint256 _value);
    event Approval (address indexed _owner, address indexed _spender, uint256 _value);
}