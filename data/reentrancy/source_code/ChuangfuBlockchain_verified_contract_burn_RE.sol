/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Changes Made:**
 * - Added external call to `IBurnRegistry(burnRegistry).onBurn(msg.sender, _value)` before state updates
 * - The external call occurs after the balance check but before the actual balance and totalSupply modifications
 * - This creates a classic reentrancy vulnerability where external code can be executed before state changes
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be effectively exploited:
 * 
 * **Transaction 1 (Setup):**
 * - Owner calls `burn(1000)` with sufficient balance
 * - The `require(balanceOf[msg.sender] >= _value)` check passes
 * - External call to `burnRegistry.onBurn()` is made
 * - The registry contract can now call back into the burn function before state updates
 * 
 * **Transaction 2+ (Exploitation):**
 * - The malicious registry contract re-enters the burn function during the callback
 * - Each re-entrant call passes the balance check because `balanceOf[msg.sender]` hasn't been updated yet
 * - Multiple burn operations can be initiated before any state updates occur
 * - This allows burning more tokens than the owner actually possesses
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation**: Each re-entrant call accumulates pending burn operations in the call stack
 * - **Persistent State Dependency**: The vulnerability exploits the fact that the balance check uses the current state, but state updates are deferred
 * - **Cross-Transaction Exploitation**: The registry contract needs to maintain state between the initial call and subsequent re-entrant calls
 * - **Complex Attack Vector**: The attacker needs to:
 *   1. First transaction: Deploy and register a malicious burn registry
 *   2. Second transaction: Trigger the initial burn that enables the reentrancy
 *   3. Multiple re-entrant calls: Execute the actual exploitation during the callback
 * 
 * **4. Realistic Integration:**
 * - Adding a burn registry notification is a legitimate feature that protocols might implement
 * - The external call placement appears natural in the function flow
 * - The vulnerability is subtle and could easily be missed in code review
 * - The onlyOwner restriction makes it appear less dangerous at first glance
 * 
 * **5. Exploitation Impact:**
 * - Owner can burn more tokens than they actually possess
 * - Total supply can be reduced below the actual circulating supply
 * - Token economics can be severely disrupted
 * - The attack requires coordination across multiple transactions, making it a true multi-transaction vulnerability
 */
pragma solidity ^0.4.24;

interface IBurnRegistry {
    function onBurn(address from, uint256 value) external;
}

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

}

contract ChuangfuBlockchain is SafeMath {
    address public owner;
    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    mapping (address => bool) public frozenAccount;
    event FrozenFunds(address target, bool frozen);

    bool lock = false;
    address public burnRegistry; // <--- Added declaration

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
        balanceOf[msg.sender] = totalSupply;
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
 

    function _transfer(address _from, address _to, uint _value) isLock internal {
        require (_to != 0x0);
        require (balanceOf[_from] >= _value);
        require (balanceOf[_to] + _value > balanceOf[_to]);
        require(!frozenAccount[_from]);
        require(!frozenAccount[_to]);
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function setBurnRegistry(address _registry) onlyOwner public {
        burnRegistry = _registry;
    }

    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn registry before state updates
        if (burnRegistry != address(0)) {
            IBurnRegistry(burnRegistry).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[_from] >= _value); 
        require(_value <= allowance[_from][msg.sender]); 
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
    
    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        emit FrozenFunds(target, freeze);
    }

    function transferBatch(address[] _to, uint256 _value) public returns (bool success) {
        for (uint i=0; i<_to.length; i++) {
            _transfer(msg.sender, _to[i], _value);
        }
        return true;
    }
}
