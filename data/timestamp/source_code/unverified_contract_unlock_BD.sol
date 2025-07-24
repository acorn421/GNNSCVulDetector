/*
 * ===== SmartInject Injection Details =====
 * Function      : unlock
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding timing-based bonus allocation logic. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variables Added** (would need to be declared in contract):
 *    - `mapping(address => uint256) lastUnlockAttempt` - tracks last unlock attempt timestamp
 *    - `mapping(address => uint256) consecutiveAttempts` - counts consecutive well-timed attempts
 * 
 * 2. **Multi-Transaction Exploitation Process**:
 *    - **Transaction 1**: First unlock call establishes baseline timestamp and initializes attempt counter
 *    - **Transaction 2**: Second unlock call within optimal time window (1-5 blocks) increments counter
 *    - **Transaction 3**: Third unlock call triggers bonus multiplier calculation based on current timestamp
 *    - **Subsequent calls**: Each additional well-timed call increases the multiplier further
 * 
 * 3. **Timestamp Dependence Vulnerability**:
 *    - The bonus multiplier uses `(now % 100) + 10` which can be manipulated by miners
 *    - Miners can adjust block timestamps to maximize the bonus (up to 109% extra tokens)
 *    - The "optimal time window" check (15-75 seconds) assumes 15-second block times but can be gamed
 * 
 * 4. **Multi-Transaction Requirement**:
 *    - Single transaction cannot exploit this - requires at least 3 transactions to trigger maximum bonus
 *    - State accumulation via `consecutiveAttempts` counter is essential
 *    - Timing manipulation requires coordination across multiple blocks/transactions
 * 
 * 5. **Realistic Attack Scenario**:
 *    - Attacker makes initial unlock call to establish timing baseline
 *    - Attacker makes 2+ additional calls within optimal windows to build up attempt counter
 *    - Attacker or cooperating miner manipulates final transaction's block timestamp to maximize `now % 100`
 *    - Results in significantly more tokens transferred than allocated (up to 2x+ the intended amount)
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

/*  ERC 20 token */
contract StandardToken is Token {

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

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
}
// requires 300,000,000 INDI deposited here
contract INDISafe {
  mapping (address => uint256) allocations;
  uint256 public unlockDate;
  address public INDI;
  uint256 public constant exponent = 10**18;

  // Added missing mappings to fix undeclared identifiers
  mapping(address => uint256) public lastUnlockAttempt;
  mapping(address => uint256) public consecutiveAttempts;

  constructor() public {
    INDI = 0xe8c09672cfb9cfce6e2edbb01057d9fa569f97c1;
    unlockDate = 1515283200;
    allocations[0x91c594706246Bed9a99CB49718b95D0F067042C8] = 300000000; 
    
  }

  function unlock() external {
    if(now < unlockDate) revert();
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Track consecutive unlock attempts for timing-based bonuses
    if (lastUnlockAttempt[msg.sender] == 0) {
        lastUnlockAttempt[msg.sender] = now;
        consecutiveAttempts[msg.sender] = 1;
    } else {
        // If attempted within optimal time window (1-5 blocks), increment counter
        uint256 timeDiff = now - lastUnlockAttempt[msg.sender];
        if (timeDiff >= 15 && timeDiff <= 75) { // 1-5 blocks assuming 15s block time
            consecutiveAttempts[msg.sender]++;
        } else {
            consecutiveAttempts[msg.sender] = 1; // Reset on poor timing
        }
        lastUnlockAttempt[msg.sender] = now;
    }
    
    uint256 entitled = allocations[msg.sender];
    
    // Apply timing-based multiplier for consecutive attempts
    uint256 multiplier = 1;
    if (consecutiveAttempts[msg.sender] >= 3) {
        // Dangerous: timestamp-dependent bonus calculation
        multiplier = 1 + (consecutiveAttempts[msg.sender] - 2) * 
                     ((now % 100) + 10) / 100; // Adds 10-109% bonus based on timestamp
    }
    
    allocations[msg.sender] = 0;
    consecutiveAttempts[msg.sender] = 0; // Reset after successful unlock
    
    if(!StandardToken(INDI).transfer(msg.sender, entitled * exponent * multiplier)) revert();
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }

}
