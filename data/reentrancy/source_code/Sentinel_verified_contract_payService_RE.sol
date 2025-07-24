/*
 * ===== SmartInject Injection Details =====
 * Function      : payService
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
 * This injection introduces a multi-transaction reentrancy vulnerability by adding an external call to the recipient (_to) before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("paymentReceived(bytes32,address,uint256)", _serviceName, _from, _value))` after initial checks but before balance updates
 * 2. Added check for contract code at `_to` address to ensure it's a contract
 * 3. Added `require(success, "Payment notification failed")` to ensure the call succeeds
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious service contract and registers it via `deployService()`
 * 2. **Transaction 2**: Attacker calls `payService()` with their malicious contract as `_to`
 * 3. **During Transaction 2**: The malicious contract's `paymentReceived()` function re-enters `payService()` with different parameters, exploiting the fact that the first call's state hasn't been updated yet
 * 4. **State Inconsistency**: The reentrancy allows the attacker to manipulate balances based on stale state from the original call
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first establish a registered service (Transaction 1) before they can call `payService()` 
 * - The vulnerability depends on the persistent state of the `services` mapping from the registration
 * - The reentrancy exploits the temporary state inconsistency during the external call, but the setup requires prior transactions
 * - The accumulated state from service registration enables the reentrancy attack in subsequent transactions
 * 
 * **Exploitation Path:**
 * 1. Register malicious service contract
 * 2. Call `payService()` with malicious contract as recipient
 * 3. Malicious contract re-enters `payService()` during `paymentReceived()` callback
 * 4. Exploit stale balance state to drain funds or manipulate accounting
 */
pragma solidity ^0.4.19;

contract Owned {
  address public owner;

  function Owned()
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
      external;
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about incoming payment (external call before state update)
        if (isContract(_to)) {
            require(_to.call(bytes4(keccak256("paymentReceived(bytes32,address,uint256)")), _serviceName, _from, _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}