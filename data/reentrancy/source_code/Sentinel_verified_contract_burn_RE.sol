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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through the following changes:
 * 
 * **Specific Changes Made:**
 * 1. Added `pendingBurns[msg.sender] += _value;` to track pending burn operations before external calls
 * 2. Introduced external call to `burnCallback` contract using existing `tokenRecipient` interface
 * 3. Moved state updates (`balanceOf` and `totalSupply` modifications) to occur AFTER the external call
 * 4. Added `pendingBurns[msg.sender] -= _value;` to clear pending burns after state updates
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1:** User calls `burn(100)` - `pendingBurns[user] = 100` is set, external call is made
 * 2. **Reentrant Call:** During external call, malicious contract calls `burn(50)` again
 * 3. **Transaction 2:** The reentrant call sees `balanceOf[user]` still contains original balance (not yet decremented)
 * 4. **State Manipulation:** Both burn operations proceed with stale balance checks, allowing over-burning
 * 5. **Result:** User can burn more tokens than they actually possess by exploiting the window between external call and state updates
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the external contract to make reentrant calls during the callback
 * - Each reentrant call is a separate transaction context that can manipulate the intermediate state
 * - The `pendingBurns` mapping accumulates state across calls, enabling exploitation only when multiple burn operations are initiated
 * - Single-transaction exploitation is impossible because the vulnerability depends on the callback mechanism and state persistence between external calls
 * - The attacker needs to deploy a malicious contract as `burnCallback` and then initiate multiple coordinated burn operations
 * 
 * **Realistic Integration:**
 * - The burn callback mechanism mimics real-world token contracts that notify external systems
 * - The `pendingBurns` tracking appears to be a legitimate feature for audit trails
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - Uses existing `tokenRecipient` interface, making it blend naturally with the contract's architecture
 */
pragma solidity ^0.4.19;

contract Owned {
  address public owner;

  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(
    address _owner)
      onlyOwner public {
        require(_owner != 0x0);

        owner = _owner;
    }
}

interface tokenRecipient {
  function receiveApproval(
    address _from,
    uint256 _value,
    address _token,
    bytes _extraData)
      public;
}

contract ERC20Token {
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;

  mapping (address => uint256) public balanceOf;
  mapping (address => mapping (address => uint256)) public allowance;
  
  // Added for burn vulnerability support
  mapping (address => uint256) public pendingBurns;
  address public burnCallback;

  event Transfer(address indexed from, address indexed to, uint256 value);

  event Burn(address indexed from, uint256 value);

  constructor(
    string _tokenName,
    string _tokenSymbol,
    uint8 _decimals,
    uint256 _totalSupply)
      public {
        name = _tokenName;
        symbol = _tokenSymbol;
        decimals = _decimals;
        totalSupply = _totalSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
    }

  function _transfer(
    address _from,
    address _to,
    uint256 _value)
      internal {
        require(_to != 0x0);
        require(_from != 0x0);
        require(_from != _to);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint256 previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

  function transfer(
    address _to,
    uint256 _value)
      public {
        _transfer(msg.sender, _to, _value);
    }

  function transferFrom(
    address _from,
    address _to,
    uint256 _value)
      public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        
        allowance[_from][msg.sender] -= _value;
        
        _transfer(_from, _to, _value);
        
        return true;
    }

  function approve(
    address _spender,
    uint256 _value)
      public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        
        return true;
    }

  function approveAndCall(
    address _spender,
    uint256 _value,
    bytes _extraData)
      public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);

        if (approve(_spender, _value)) {
          spender.receiveApproval(msg.sender, _value, this, _extraData);
          
          return true;
        }
    }

  function burn(
    uint256 _value)
      public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add pending burn tracking for multi-transaction exploitation
        pendingBurns[msg.sender] += _value;

        // External call to user-controlled contract BEFORE state updates
        // This enables reentrancy where the external contract can call back
        if (burnCallback != address(0)) {
            tokenRecipient(burnCallback).receiveApproval(msg.sender, _value, this, "");
        }

        // State updates happen AFTER external call - classic reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burn only after all state updates
        pendingBurns[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        Burn(msg.sender, _value);

        return true;
    }

  function burnFrom(
    address _from,
    uint256 _value)
      public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);

        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;

        Burn(_from, _value);

        return true;
    }
}

contract Sentinel is Owned, ERC20Token {
  mapping (bytes32 => address) public services;

  constructor(
    string _tokenName,
    string _tokenSymbol,
    uint8 _decimals,
    uint256 _totalSupply)
      ERC20Token(_tokenName, _tokenSymbol, _decimals, _totalSupply) public {
    }

  function deployService(
    bytes32 _serviceName,
    address _serviceAddress)
      onlyOwner public {
        services[_serviceName] = _serviceAddress;
    }

  function payService(
    bytes32 _serviceName,
    address _from,
    address _to,
    uint256 _value)
      public {
        require(msg.sender != 0x0);
        require(services[_serviceName] != 0x0);
        require(msg.sender == services[_serviceName]);
        require(_from != 0x0);
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint256 previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
}
