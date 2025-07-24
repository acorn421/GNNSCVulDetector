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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This violates the Checks-Effects-Interactions (CEI) pattern and allows reentrancy attacks.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to` address using low-level call with `onTokenReceived` signature
 * 2. Positioned this external call BEFORE state updates (balances and allowances)
 * 3. Added contract existence check using `_to.code.length > 0`
 * 4. Made the external call required to succeed, creating a dependency
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker deploys malicious contract and gets approval for large token amount
 * - **Transaction 2**: Third party calls `transferFrom` to send tokens to attacker's malicious contract
 * - **During Transaction 2**: Malicious contract's `onTokenReceived` function is called BEFORE state updates
 * - **Reentrancy**: Attacker re-enters `transferFrom` multiple times before original state is updated
 * - **Result**: Attacker drains more tokens than approved allowance
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Setup**: Initial allowance must be established in separate transaction
 * 2. **Persistent State**: The vulnerability exploits the fact that `balances` and `allowed` mappings persist between transactions
 * 3. **External Dependency**: Requires external contract deployment and setup before exploitation
 * 4. **Allowance Mechanism**: Multiple calls can drain different amounts based on accumulated allowance state
 * 
 * The vulnerability requires the allowance system's stateful nature - attackers must first obtain approvals, then exploit the reentrancy when those approvals are used across multiple transactions.
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

    // Changed to constructor for pragma ^0.4.11
    function mAlek() public {
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
        balances[msg.sender] = balances[msg.sender].add(tokens);
        _totalSupply = _totalSupply.add(tokens);
        owner.transfer(msg.value);
    }

    function mintTokens(address _to, uint256 _value) public {
        require (owner == msg.sender);        
        balances[_to] = balances[_to].add(_value*10**18);
        _totalSupply = _totalSupply.add(_value*10**18);
        emit Transfer(0x0, this, _value*10**18);
        emit Transfer(this, _to, _value*10**18);
    }

    function totalSupply () public constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf (address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function transfer (address _to, uint256 _value) public returns (bool success) {
        require (balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;        
    }

    function transferFrom (address _from, address _to, uint256 _value) public returns (bool success) {
        require (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Use extcodesize workaround for address.code.length in 0.4.11
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            bool notifySuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            require(notifySuccess);
        }
        
        // State updates happen AFTER external call - violates CEI pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve (address _spender, uint256 _value) public returns (bool success) {
        allowed [msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance (address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer (address indexed _from, address indexed _to, uint256 _value);
    event Approval (address indexed _owner, address indexed _spender, uint256 _value);
}
