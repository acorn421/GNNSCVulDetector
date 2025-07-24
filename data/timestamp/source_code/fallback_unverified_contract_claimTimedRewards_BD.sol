/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimedRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction staking reward system. The vulnerability is stateful and requires multiple transactions to exploit:
 * 
 * 1. **State Setup Transaction**: User calls startStaking() to stake tokens and initialize lastClaimTime
 * 2. **Exploitation Transactions**: User repeatedly calls claimTimedRewards() where miners can manipulate block timestamps to:
 *    - Artificially increase time elapsed between claims
 *    - Manipulate reward calculations by controlling the 'now' timestamp
 *    - Bypass intended time restrictions on reward claiming
 * 
 * The vulnerability is stateful because:
 * - It relies on persistent state variables (lastClaimTime, stakingBalance)
 * - Each claim updates the lastClaimTime state for future calculations
 * - The exploit requires building up staking balance over time
 * - Multiple transactions are needed to accumulate significant rewards
 * 
 * The timestamp dependence allows malicious miners to manipulate block timestamps within acceptable bounds to maximize their reward claims, making this a realistic multi-transaction vulnerability.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-010-23
*/

pragma solidity ^0.4.16;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns(uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns(uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a + b;
    assert(c >= a && c >= b);
    return c;
  }

}

contract BTCB is SafeMath {
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;
  address public owner;

  /* This creates an array with all balances */
  mapping(address => uint256) public balanceOf;
  mapping(address => uint256) public freezeOf;
  mapping(address => mapping(address => uint256)) public allowance;

  /* This generates a public event on the blockchain that will notify clients */
  event Transfer(address indexed from, address indexed to, uint256 value);

  /* This notifies clients about the amount burnt */
  event Burn(address indexed from, uint256 value);

  /* This notifies clients about the amount frozen */
  event Freeze(address indexed from, uint256 value);

  /* This notifies clients about the amount unfrozen */
  event Unfreeze(address indexed from, uint256 value);

  event Approval(address indexed _owner, address indexed _spender, uint256 _value);
  /* Initializes contract with initial supply tokens to the creator of the contract */
  
  // === FALLBACK INJECTION: Timestamp Dependence ===
  // These variables and functions should be declared at contract scope, not inside the constructor.
  mapping(address => uint256) public lastClaimTime;
  mapping(address => uint256) public stakingBalance;
  uint256 public rewardRate = 100; // tokens per day
  uint256 public stakingStartTime;

  constructor() public{
    balanceOf[msg.sender] = 3000000000000;       // Give the creator all initial tokens
    totalSupply = 3000000000000;                 // Update total supply
    name = 'Bitcoin Bless';                          // Set the name for display purposes
    symbol = 'BTCB';                          // Set the symbol for display purposes
    decimals = 8;                            // Amount of decimals for display purposes
    owner = msg.sender;
  }

  function startStaking(uint256 _amount) public returns(bool success) {
    if (_amount <= 0) revert();
    if (balanceOf[msg.sender] < _amount) revert();
    
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
    stakingBalance[msg.sender] = SafeMath.safeAdd(stakingBalance[msg.sender], _amount);
    
    if (stakingStartTime == 0) {
      stakingStartTime = now;
    }
    
    if (lastClaimTime[msg.sender] == 0) {
      lastClaimTime[msg.sender] = now;
    }
    
    return true;
  }
  
  function claimTimedRewards() public returns(bool success) {
    if (stakingBalance[msg.sender] == 0) revert();
    if (lastClaimTime[msg.sender] == 0) revert();
    
    // Vulnerable: Using block.timestamp directly for reward calculation
    uint256 timeElapsed = now - lastClaimTime[msg.sender];
    uint256 rewardAmount = SafeMath.safeMul(SafeMath.safeMul(stakingBalance[msg.sender], rewardRate), timeElapsed) / (1 days * 10000);
    
    // Vulnerable: Not checking if enough time has passed, allowing rapid claims
    if (rewardAmount > 0) {
      balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], rewardAmount);
      totalSupply = SafeMath.safeAdd(totalSupply, rewardAmount);
      lastClaimTime[msg.sender] = now; // Update claim time using vulnerable timestamp
      
      emit Transfer(address(0), msg.sender, rewardAmount);
    }
    
    return true;
  }
  
  function unstakeTokens(uint256 _amount) public returns(bool success) {
    if (_amount <= 0) revert();
    if (stakingBalance[msg.sender] < _amount) revert();
    
    stakingBalance[msg.sender] = SafeMath.safeSub(stakingBalance[msg.sender], _amount);
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _amount);
    
    return true;
  }
  // === END FALLBACK INJECTION ===

  /* Send tokens */
  function transfer(address _to, uint256 _value) public returns(bool){
    if (_to == 0x0) return false;                               // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) return false;
    if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
    emit Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
	return true;
  }

  /* Allow another contract to spend some tokens in your behalf */
  function approve(address _spender, uint256 _value) public returns(bool success) {
    require((_value == 0) || (allowance[msg.sender][_spender] == 0));
    allowance[msg.sender][_spender] = _value;
	emit Approval(msg.sender, _spender, _value);
    return true;
  }

  /* Transfer tokens */
  function transferFrom(address _from, address _to, uint256 _value) public returns(bool success) {
    if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) revert();
    if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
    if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
    balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
    allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
    emit Transfer(_from, _to, _value);
    return true;
  }

  /* Destruction of the token */
  function burn(uint256 _value) public returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
    totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
    emit Burn(msg.sender, _value);
    return true;
  }

  function freeze(uint256 _value) public returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
    freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
    emit Freeze(msg.sender, _value);
    return true;
  }

  function unfreeze(uint256 _value) public returns(bool success) {
    if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
    emit Unfreeze(msg.sender, _value);
    return true;
  }

  /* Prevents accidental sending of Ether */
  function () public{
    revert();
  }
  /* token code by kay */
}
