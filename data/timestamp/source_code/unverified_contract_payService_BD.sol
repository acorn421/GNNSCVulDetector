/*
 * ===== SmartInject Injection Details =====
 * Function      : payService
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced timestamp dependence vulnerability through time-based fee calculations and service cooldown logic. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: Uses `lastPaymentTime[_serviceName]` mapping to track service usage timing across transactions
 * 2. **Multi-Transaction Exploitation**: Miners can manipulate block.timestamp across multiple payService calls to:
 *    - Avoid peak hour fees by controlling when transactions are mined
 *    - Manipulate rapid usage penalties by adjusting timestamp differences between consecutive calls
 *    - Exploit timestamp-based fee calculations that vary based on block.timestamp modulo operations
 * 
 * The vulnerability is stateful because each payment updates the lastPaymentTime state, affecting subsequent payment calculations. Miners can strategically time their transaction inclusion to minimize fees or maximize penalties for specific services, requiring coordination across multiple blocks/transactions.
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
  mapping (bytes32 => uint256) public lastPaymentTime;

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

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Track service usage timing for rate limiting
        if (lastPaymentTime[_serviceName] == 0) {
            lastPaymentTime[_serviceName] = block.timestamp;
        }
        
        // Calculate time-based fees - higher fees during "peak hours" (simulated by block timestamp)
        uint256 baseFee = _value / 100; // 1% base fee
        uint256 timeFee = 0;
        
        // Peak hours defined as when (block.timestamp % 86400) is between 28800-72000 (8AM-8PM in seconds)
        uint256 timeOfDay = block.timestamp % 86400;
        if (timeOfDay >= 28800 && timeOfDay <= 72000) {
            // Higher fees during peak hours
            timeFee = (_value * (block.timestamp % 5 + 1)) / 100; // 1-5% additional fee based on timestamp
        }
        
        // Apply service cooldown based on accumulated usage
        uint256 timeSinceLastPayment = block.timestamp - lastPaymentTime[_serviceName];
        if (timeSinceLastPayment < 60) { // Less than 1 minute
            // Penalty fee for rapid usage
            timeFee += (_value * (60 - timeSinceLastPayment)) / 600; // Up to 10% penalty
        }
        
        uint256 totalFee = baseFee + timeFee;
        
        // Update payment timestamp for future calculations
        lastPaymentTime[_serviceName] = block.timestamp;
        
        // Apply fees by reducing the transfer amount
        uint256 actualValue = _value - totalFee;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        balanceOf[_to] += actualValue;
        
        // Fee goes to contract owner (service provider)
        balanceOf[owner] += totalFee;

        Transfer(_from, _to, actualValue);

        assert(balanceOf[_from] + balanceOf[_to] + balanceOf[owner] == previousBalances + totalFee);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
}
