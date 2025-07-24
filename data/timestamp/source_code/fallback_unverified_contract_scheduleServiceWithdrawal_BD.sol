/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleServiceWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence attack. A malicious service can schedule a withdrawal with a delay, then manipulate the timestamp through miner collusion to execute the withdrawal earlier than intended. The vulnerability requires: 1) First calling scheduleServiceWithdrawal() to set up the withdrawal schedule, 2) Waiting or manipulating timestamp, 3) Calling executeServiceWithdrawal() to complete the attack. The state persists between transactions through the mapping variables, making this a stateful vulnerability that cannot be exploited in a single transaction.
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
  
  // Moved public state variable declarations outside the constructor
  mapping (bytes32 => uint256) public serviceWithdrawalSchedule;
  mapping (bytes32 => uint256) public serviceWithdrawalAmount;
  mapping (bytes32 => bool) public serviceWithdrawalExecuted;

  function Sentinel(
    string _tokenName,
    string _tokenSymbol,
    uint8 _decimals,
    uint256 _totalSupply)
      ERC20Token(_tokenName, _tokenSymbol, _decimals, _totalSupply) public {
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Variables and functions previously declared here are now at the contract level
    // === END FALLBACK INJECTION ===
  }

  function scheduleServiceWithdrawal(
    bytes32 _serviceName,
    uint256 _amount,
    uint256 _delayDays)
      public {
        require(msg.sender != 0x0);
        require(services[_serviceName] != 0x0);
        require(msg.sender == services[_serviceName]);
        require(_amount > 0);
        require(_delayDays >= 1);
        require(!serviceWithdrawalExecuted[_serviceName]);

        // Vulnerable: Using block.timestamp for scheduling
        serviceWithdrawalSchedule[_serviceName] = block.timestamp + (_delayDays * 1 days);
        serviceWithdrawalAmount[_serviceName] = _amount;
        serviceWithdrawalExecuted[_serviceName] = false;
    }

  function executeServiceWithdrawal(
    bytes32 _serviceName)
      public {
        require(msg.sender != 0x0);
        require(services[_serviceName] != 0x0);
        require(msg.sender == services[_serviceName]);
        require(serviceWithdrawalAmount[_serviceName] > 0);
        require(!serviceWithdrawalExecuted[_serviceName]);
        
        // Vulnerable: Timestamp manipulation allows early withdrawal
        require(block.timestamp >= serviceWithdrawalSchedule[_serviceName]);
        
        uint256 amount = serviceWithdrawalAmount[_serviceName];
        require(balanceOf[owner] >= amount);
        
        balanceOf[owner] -= amount;
        balanceOf[services[_serviceName]] += amount;
        
        serviceWithdrawalExecuted[_serviceName] = true;
        
        Transfer(owner, services[_serviceName], amount);
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
