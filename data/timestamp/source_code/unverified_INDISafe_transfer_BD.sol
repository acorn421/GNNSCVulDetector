/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a time-based daily transfer limit mechanism that uses block.timestamp for resetting transfer quotas. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **State Variables Required**: The contract would need additional state variables:
 *    - `mapping(address => uint256) dailyTransferAmount` - tracks accumulated transfers
 *    - `mapping(address => uint256) lastResetTime` - stores last reset timestamp per user
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: User makes a transfer, establishing their daily limit and reset time
 *    - Transaction 2: Miner manipulates block.timestamp to artificially advance time by 24+ hours
 *    - Transaction 3: User can now bypass the daily limit as their quota has been "reset"
 * 
 * 3. **Timestamp Manipulation**: Miners can manipulate block.timestamp within a 900-second window to:
 *    - Prematurely reset daily limits for users
 *    - Extend the effective duration of daily limits
 *    - Allow users to exceed intended transfer restrictions
 * 
 * 4. **Stateful Nature**: The vulnerability requires persistent state changes across multiple transactions - the daily transfer amounts and reset times must be stored and modified over time to create the exploitable condition.
 * 
 * The vulnerability maintains the original function's behavior while introducing a realistic security feature (daily limits) that creates a timestamp dependence vulnerability requiring multiple transactions to exploit.
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    mapping (address => uint256) balances;
    mapping (address => uint256) dailyTransferAmount;
    mapping (address => uint256) lastResetTime;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success) {
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      // Time-based daily transfer limit that resets every 24 hours
      if (block.timestamp >= lastResetTime[msg.sender] + 86400) {
        dailyTransferAmount[msg.sender] = 0;
        lastResetTime[msg.sender] = block.timestamp;
      }
      
      // Check if transfer would exceed daily limit (10% of balance)
      uint256 dailyLimit = balances[msg.sender] / 10;
      if (dailyTransferAmount[msg.sender] + _value > dailyLimit) {
        return false;
      }
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      if (balances[msg.sender] >= _value && _value > 0) {
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        dailyTransferAmount[msg.sender] += _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
      } else {
        return false;
      }
    }
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


/*  ERC 20 token */
contract StandardToken is Token {

    mapping (address => mapping (address => uint256)) allowed;

    function transfer(address _to, uint256 _value) returns (bool success) {
      if (balances[msg.sender] >= _value && _value > 0) {
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
      } else {
        return false;
      }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
      if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
      } else {
        return false;
      }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }
}
// requires 300,000,000 INDI deposited here
contract INDISafe {
  mapping (address => uint256) allocations;
  uint256 public unlockDate;
  address public INDI;
  uint256 public constant exponent = 10**18;

  constructor() public {
    INDI = 0xe8c09672cfb9cfce6e2edbb01057d9fa569f97c1;
    unlockDate = 1515283200;
    allocations[0x91c594706246Bed9a99CB49718b95D0F067042C8] = 300000000; 
    
  }

  function unlock() external {
    if(now < unlockDate) revert();
    uint256 entitled = allocations[msg.sender];
    allocations[msg.sender] = 0;
    if(!StandardToken(INDI).transfer(msg.sender, entitled * exponent)) revert();
  }

}
