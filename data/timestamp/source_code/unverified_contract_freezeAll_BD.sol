/*
 * ===== SmartInject Injection Details =====
 * Function      : freezeAll
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through:
 * 
 * 1. **State Variable Introduction**: Added `lastFreezeTime` state variable to track freeze timestamps
 * 2. **Time-Based Cooldown Logic**: Implemented 24-hour cooldown between freeze operations using `block.timestamp`
 * 3. **Emergency Unfreeze Window**: Created 1-hour window for emergency unfreezing using timestamp comparison
 * 4. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Creator calls freezeAll() to freeze, sets lastFreezeTime to current block.timestamp
 *    - Transaction 2+: Miners can manipulate block.timestamp (±900 seconds) to bypass cooldowns or extend/close emergency windows
 *    - Transaction N: Exploit timing manipulation to freeze/unfreeze at advantageous moments
 * 
 * **Multi-Transaction Requirements Met**:
 * - State persists between transactions through `lastFreezeTime`
 * - First transaction establishes timing baseline
 * - Subsequent transactions can exploit timestamp manipulation
 * - Cannot be exploited atomically in single transaction
 * 
 * **Realistic Vulnerability Characteristics**:
 * - Common pattern in DeFi contracts with time-based restrictions
 * - Miners can manipulate block.timestamp within bounds
 * - Emergency mechanisms often rely on timestamp comparisons
 * - Affects critical contract functionality (token transfers)
 */
/**
 *Submitted for verification at Etherscan.io on 2019-10-21
*/

pragma solidity ^0.4.6;

contract SprintBit {

  string public name = "SprintBit";
  string public symbol = "SBT";
  uint public decimals = 18;
  uint public INITIAL_SUPPLY = 100000000000000000000000000;

  mapping(address => uint) balances;
  mapping (address => mapping (address => uint)) allowed;
  uint256 public _totalSupply;
  address public _creator;
  bool bIsFreezeAll = false;
  uint256 public lastFreezeTime; // Added declaration for lastFreezeTime
  
  event Transfer(address indexed from, address indexed to, uint value);
  event Approval(address indexed owner, address indexed spender, uint value);
  
  function safeSub(uint a, uint b) internal returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint a, uint b) internal returns (uint) {
    uint c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
  function totalSupply() public constant returns (uint256 total) {
	total = _totalSupply;
  }

  function transfer(address _to, uint _value) public returns (bool success) {
    require(bIsFreezeAll == false);
    balances[msg.sender] = safeSub(balances[msg.sender], _value);
    balances[_to] = safeAdd(balances[_to], _value);
    Transfer(msg.sender, _to, _value);
    return true;
  }

  function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
    require(bIsFreezeAll == false);
    uint _allowance = allowed[_from][msg.sender]; // changed var to uint
    balances[_to] = safeAdd(balances[_to], _value);
    balances[_from] = safeSub(balances[_from], _value);
    allowed[_from][msg.sender] = safeSub(_allowance, _value);
    Transfer(_from, _to, _value);
    return true;
  }

  function balanceOf(address _owner) public constant returns (uint balance) {
    return balances[_owner];
  }

  function approve(address _spender, uint _value) public returns (bool success) {
	require(bIsFreezeAll == false);
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public constant returns (uint remaining) {
    return allowed[_owner][_spender];
  }

  function freezeAll() public 
  {
	require(msg.sender == _creator);
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	
	// Time-based cooldown mechanism with timestamp dependence vulnerability
	if (bIsFreezeAll == false) {
		// Require 24-hour cooldown between freeze operations
		require(block.timestamp >= lastFreezeTime + 86400);
		lastFreezeTime = block.timestamp;
	} else {
		// Emergency unfreeze allowed within 1 hour of freeze
		require(block.timestamp <= lastFreezeTime + 3600);
	}
	
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	bIsFreezeAll = !bIsFreezeAll;
  }
  
  constructor() public {
        _totalSupply = INITIAL_SUPPLY;
	_creator = 0xc66c4A406ff17E976C06025a750ED3723EDA174c;
	balances[_creator] = INITIAL_SUPPLY;
	bIsFreezeAll = false;
    lastFreezeTime = 0;
  }
  
  function destroy() public  {
	require(msg.sender == _creator);
	selfdestruct(_creator);
  }

}
