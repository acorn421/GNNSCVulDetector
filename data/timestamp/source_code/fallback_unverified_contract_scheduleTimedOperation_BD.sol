/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedOperation
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The vulnerability requires: 1) First transaction to schedule a timed operation with funds locked, 2) Second transaction to execute the operation based on timestamp comparison. The vulnerability allows miners to manipulate block timestamps within certain bounds to either delay or accelerate the execution of timed operations, potentially causing financial losses or unfair advantages. The state persists between transactions through the timedOperations mapping.
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract GDU is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    
    uint256 createTime;
    
    address addr1;
    address addr2;
    address addr3;
    address addr4;
    

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
    
    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    struct TimedOperation {
        uint256 targetTime;
        uint256 amount;
        address beneficiary;
        bool executed;
    }
    
    mapping(uint256 => TimedOperation) public timedOperations;
    uint256 public nextOperationId;
    
    event TimedOperationScheduled(uint256 operationId, uint256 targetTime, uint256 amount, address beneficiary);
    event TimedOperationExecuted(uint256 operationId, address beneficiary, uint256 amount);
    // === END FALLBACK INJECTION ===

    uint256[] mouthUnlockList;
    uint256[] yearUnlockList;
    mapping (address => uint256[]) addrCanWithdraw;
    
    modifier onlyMounthWithdrawer {
        require(msg.sender == addr1 || msg.sender == addr2 || msg.sender == addr3 );
        _;
    }
    modifier onlyYearWithdrawer {
        require(msg.sender == addr4 );
        _;
    }
    
    function GDU() {
        balanceOf[msg.sender] = 15 * (10 ** 8) * (10 ** 18);              // Give the creator all initial tokens
        totalSupply =  100 * (10 ** 8) * (10 ** 18);                        // Update total supply
        name = "GD Union";                                   // Set the name for display purposes
        symbol = "GDU";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        owner = msg.sender;
        createTime = now;
        
        addr1 = 0xa201967b67fA4Da2F7f4Cc2a333d2594fC44d350;
        addr2 = 0xC49909D6Cc0B460ADB33E591eC314DC817E9d200;
        addr3 = 0x455A3Ac6f11e6c301E4e5996F26EfaA76c549474;
        addr4 = 0xA93EAe1Db16F8710293a505289B0c8C34af5332F;
    
        for(int i = 0;i < 10;i++) {
            mouthUnlockList.push(0.5 * (10 ** 8) * (10 ** 18));
        }
        addrCanWithdraw[addr1] = mouthUnlockList;
        addrCanWithdraw[addr2] = mouthUnlockList;
        addrCanWithdraw[addr3] = mouthUnlockList;
        
        for(uint256 year = 0;year < 4;year++) {
            yearUnlockList.push(10 * (10 ** 8) * (10 ** 18) + year * 5 * (10 ** 8) * (10 ** 18));
        }
        addrCanWithdraw[addr4] = yearUnlockList;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleTimedOperation(uint256 _amount, address _beneficiary, uint256 _delayInSeconds) returns (uint256 operationId) {
        if (_amount <= 0) throw;
        if (_beneficiary == 0x0) throw;
        if (balanceOf[msg.sender] < _amount) throw;
        
        // Calculate target time using current timestamp
        uint256 targetTime = now + _delayInSeconds;
        
        // Create operation
        operationId = nextOperationId++;
        timedOperations[operationId] = TimedOperation({
            targetTime: targetTime,
            amount: _amount,
            beneficiary: _beneficiary,
            executed: false
        });
        
        // Lock the funds by transferring to contract
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
        balanceOf[this] = SafeMath.safeAdd(balanceOf[this], _amount);
        
        TimedOperationScheduled(operationId, targetTime, _amount, _beneficiary);
        return operationId;
    }
    
    function executeTimedOperation(uint256 _operationId) returns (bool success) {
        TimedOperation storage operation = timedOperations[_operationId];
        
        if (operation.executed) throw;
        if (operation.amount <= 0) throw;
        
        // VULNERABILITY: Using 'now' for time comparison allows miner manipulation
        // The miner can manipulate block timestamp within certain bounds
        if (now < operation.targetTime) throw;
        
        // Execute the operation
        operation.executed = true;
        balanceOf[this] = SafeMath.safeSub(balanceOf[this], operation.amount);
        balanceOf[operation.beneficiary] = SafeMath.safeAdd(balanceOf[operation.beneficiary], operation.amount);
        
        TimedOperationExecuted(_operationId, operation.beneficiary, operation.amount);
        Transfer(this, operation.beneficiary, operation.amount);
        return true;
    }
    // === END FALLBACK INJECTION ===
    
    function withdrawUnlockMonth() onlyMounthWithdrawer {
        uint256 currentTime = now;
        uint256 times = (currentTime  - createTime) / 2190 hours;
        for(uint256 i = 0;i < times; i++) {
            balanceOf[msg.sender] += addrCanWithdraw[msg.sender][i];
            addrCanWithdraw[msg.sender][i] = 0;
        }
    }
    
    function withdrawUnlockYear() onlyYearWithdrawer {
        uint256 currentTime = now;
        require((currentTime  - createTime) > 0);
        uint256 times = (currentTime  - createTime) / 1 years;
        require(times <= 3);
        for(uint256 i = 0;i < times; i++) {
            balanceOf[msg.sender] += addrCanWithdraw[msg.sender][i];
            addrCanWithdraw[msg.sender][i] = 0;
        }
    }
    
    

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
    
    // transfer balance to owner
    function withdrawEther(uint256 amount) payable {
        if(msg.sender != owner)throw;
        owner.transfer(amount);
    }
    
    // can accept ether
    function() payable {
    }
}
