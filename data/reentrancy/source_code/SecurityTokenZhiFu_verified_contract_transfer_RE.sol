/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism after balance updates. The vulnerability exploits the fact that:
 * 
 * 1. **State Changes Persist**: Balance updates are committed to storage before the external call
 * 2. **Multi-Transaction Exploitation**: Requires multiple transactions to drain funds:
 *    - Transaction 1: Legitimate transfer triggers callback, malicious contract can call transfer again
 *    - Transaction 2+: Each recursive call can transfer more tokens using updated balances
 *    - The vulnerability accumulates over multiple calls as balances persist between transactions
 * 
 * 3. **Realistic Callback Pattern**: The onTokenReceived callback is a common pattern in token contracts for notifying recipients
 * 
 * **Exploitation Scenario:**
 * - Attacker deploys malicious contract with onTokenReceived function
 * - Transaction 1: Victim transfers tokens to malicious contract
 * - During callback: Malicious contract calls transfer() again before original transaction completes
 * - Each recursive call uses the updated balance state from previous calls
 * - Multiple transactions can drain the sender's balance progressively
 * 
 * **Multi-Transaction Requirement:**
 * The vulnerability requires multiple function calls because:
 * - Each call to transfer() updates persistent state (balances mapping)
 * - The callback mechanism allows for recursive calls that compound the effect
 * - The exploit builds up over multiple transactions as state changes accumulate
 * - Single transaction exploitation is limited by gas constraints, but multi-transaction allows unlimited drainage
 */
pragma solidity ^0.4.24;

library SafeMath {

 
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); 
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }

  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract SecurityTokenZhiFu {
    mapping(address => uint256) public balances;
    mapping(address => mapping (address => uint256)) public allowed;
    using SafeMath for uint256;
    address public owner;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    uint256 private constant MAX_UINT256 = 2**256 -1 ;

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    
    bool lock = false;

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        owner = msg.sender;
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
        
    }
	
	
	modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier isLock {
        require(!lock);
        _;
    }
    
    function setLock(bool _lock) onlyOwner public{
        lock = _lock;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
	
	

    function transfer(
        address _to,
        uint256 _value
    ) public returns (bool) {
        require(balances[msg.sender] >= _value);
        require(msg.sender == _to || balances[_to] <= MAX_UINT256 - _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call to potentially malicious contract after state update
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) public returns (bool) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value);
        require(_from == _to || balances[_to] <= MAX_UINT256 -_value);
        require(allowance >= _value);
        balances[_from] -= _value;
        balances[_to] += _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(
        address _owner
    ) public view returns (uint256) {
        return balances[_owner];
    }

    function approve(
        address _spender,
        uint256 _value
    ) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    ) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
}
