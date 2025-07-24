/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a burn notification callback system with persistent state tracking. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added `burnPending` mapping to track ongoing burn operations
 * 2. Added external call to notify token holder before state updates
 * 3. Used try-catch to handle callback failures gracefully
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker sets up a malicious contract as token holder and gets approval for burning
 * 2. **Transaction 2**: Attacker calls burnFrom(), triggering the callback which can:
 *    - Manipulate allowances for future transactions
 *    - Set up state for later exploitation
 *    - Call approve() to reset allowances after burn starts
 * 3. **Transaction 3+**: Attacker exploits the inconsistent state between callback and burn completion
 * 
 * **Why Multi-Transaction Required:**
 * - The `burnPending` flag prevents immediate reentrancy within the same transaction
 * - The vulnerability exploits the time window between the callback and final state updates
 * - Attackers must prepare malicious contracts in advance (separate transaction)
 * - The exploit requires coordinated sequence of approve/burnFrom calls across multiple blocks
 * - State persistence allows attackers to manipulate allowances between the callback and burn completion
 * 
 * **Realistic Scenario:**
 * A malicious contract receives the burn notification and immediately calls approve() to reset allowances, or manipulates other contract state that affects subsequent burns. This creates a race condition where multiple burn operations can occur with stale allowance values.
 */
pragma solidity ^0.4.19;

contract Owned {
  address public owner;

  function Owned(
    )
      public {
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

  event Transfer(address indexed from, address indexed to, uint256 value);

  event Burn(address indexed from, uint256 value);

  function ERC20Token(
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

        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;

        Burn(msg.sender, _value);

        return true;
    }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping (address => bool) private burnPending;
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  function burnFrom(
    address _from,
    uint256 _value)
      public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(!burnPending[_from]); // Prevent concurrent burns

        burnPending[_from] = true;
        
        // Notify the token holder before burning (external call)
        if (_from != msg.sender) {
            // In Solidity 0.4.x, can't check contract code length directly
            // Instead, use extcodesize via assembly
            uint codesize = 0;
            assembly { codesize := extcodesize(_from) }
            if (codesize > 0) {
                tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        burnPending[_from] = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);

        return true;
    }
}

contract Sentinel is Owned, ERC20Token {
  mapping (bytes32 => address) public services;

  function Sentinel(
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
