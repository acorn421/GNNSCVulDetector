/*
 * ===== SmartInject Injection Details =====
 * Function      : CreateToken
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based bonus system. The contract now tracks consecutive token creation transactions within hourly windows, awarding increasing bonuses for rapid successive calls. This creates a multi-transaction vulnerability where miners can manipulate block timestamps across multiple transactions to maximize token generation bonuses.
 * 
 * **Specific Changes Made:**
 * 1. **Added time-based state tracking**: The contract now maintains `lastBonusReset`, `bonusMultiplier`, and `consecutiveBonusBlocks` state variables that persist between transactions
 * 2. **Implemented time window logic**: Uses `block.timestamp` to determine if transactions fall within the same hourly bonus window
 * 3. **Created accumulating bonus system**: Each successive transaction within the same hour increases the bonus multiplier (up to 2x)
 * 4. **Applied bonus to token creation**: The actual token amount is multiplied by the current bonus multiplier
 * 
 * **Multi-Transaction Exploitation:**
 * A malicious miner can exploit this across multiple transactions by:
 * 1. **Transaction 1**: Call CreateToken() to establish initial bonus state and receive base tokens
 * 2. **Transaction 2**: Manipulate block timestamp to appear within the same hour window, call CreateToken() again to receive 1.1x bonus
 * 3. **Transaction 3**: Continue manipulating timestamps, call CreateToken() to receive 1.2x bonus
 * 4. **Subsequent transactions**: Keep exploiting within the same manipulated time window to receive up to 2x bonus tokens
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - The vulnerability requires building up the `consecutiveBonusBlocks` counter across multiple function calls
 * - Each transaction depends on the state established by previous transactions
 * - Single transaction cannot accumulate the bonus multiplier - it requires the stateful progression
 * - The exploit becomes more profitable with more transactions in the sequence
 * - Miners need multiple blocks to effectively manipulate timestamps while maintaining the bonus window
 */
pragma solidity ^0.4.17;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }

  function min(uint a, uint b) internal pure returns (uint256) {
    return a < b ? a : b;
  }
}

//This is the basic wrapped Ether contract. 
//All money deposited is transformed into ERC20 tokens at the rate of 1 wei = 1 token
contract Wrapped_Ether {

  using SafeMath for uint256;

  /*Variables*/

  //ERC20 fields
  string public name = "Wrapped Ether";
  uint public total_supply;

  //ERC20 fields
  mapping(address => uint) balances;
  mapping(address => mapping (address => uint)) allowed;

  // Time-based bonus system state variables
  uint public lastBonusReset = now;
  uint public bonusMultiplier = 100; // 100 = 1.0x, 150 = 1.5x
  uint public consecutiveBonusBlocks = 0;

  /*Events*/

  event Transfer(address indexed _from, address indexed _to, uint _value);
  event Approval(address indexed _owner, address indexed _spender, uint _value);
  event StateChanged(bool _success, string _message);

  /*Functions*/

  //This function creates tokens equal in value to the amount sent to the contract
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
  function CreateToken() public payable {
    require(msg.value > 0);
    
    // Time-based bonus system that accumulates over multiple transactions
    uint currentTime = now;
    
    // Reset bonus tracking if more than 1 hour has passed
    if (currentTime - lastBonusReset > 3600) {
      consecutiveBonusBlocks = 0;
      bonusMultiplier = 100;
      lastBonusReset = currentTime;
    }
    
    // Increase bonus multiplier for consecutive blocks within same hour
    if (currentTime - lastBonusReset < 3600) {
      consecutiveBonusBlocks++;
      // Bonus increases with consecutive transactions in same time window
      bonusMultiplier = 100 + (consecutiveBonusBlocks * 10); // Up to 2x bonus
    }
    
    // Apply time-based bonus to token creation
    uint bonusTokens = msg.value.mul(bonusMultiplier).div(100);
    
    balances[msg.sender] = balances[msg.sender].add(bonusTokens);
    total_supply = total_supply.add(bonusTokens);
    
    // Update last bonus reset time for next transaction
    lastBonusReset = currentTime;
  }
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  /*
  * This function 'unwraps' an _amount of Ether in the sender's balance by transferring Ether to them
  *
  * @param "_amount": The amount of the token to unwrap
  */
  function withdraw(uint _value) public {
    balances[msg.sender] = balances[msg.sender].sub(_value);
    total_supply = total_supply.sub(_value);
    msg.sender.transfer(_value);
  }

  //Returns the balance associated with the passed in _owner
  function balanceOf(address _owner) public constant returns (uint bal) { return balances[_owner]; }

  /*
  * Allows for a transfer of tokens to _to
  *
  * @param "_to": The address to send tokens to
  * @param "_amount": The amount of tokens to send
  */
  function transfer(address _to, uint _amount) public returns (bool success) {
    if (balances[msg.sender] >= _amount
    && _amount > 0
    && balances[_to] + _amount > balances[_to]) {
      balances[msg.sender] = balances[msg.sender].sub(_amount);
      balances[_to] = balances[_to].add(_amount);
      Transfer(msg.sender, _to, _amount);
      return true;
    } else {
      return false;
    }
  }

  /*
  * Allows an address with sufficient spending allowance to send tokens on the behalf of _from
  *
  * @param "_from": The address to send tokens from
  * @param "_to": The address to send tokens to
  * @param "_amount": The amount of tokens to send
  */
  function transferFrom(address _from, address _to, uint _amount) public returns (bool success) {
    if (balances[_from] >= _amount
    && allowed[_from][msg.sender] >= _amount
    && _amount > 0
    && balances[_to] + _amount > balances[_to]) {
      balances[_from] = balances[_from].sub(_amount);
      allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
      balances[_to] = balances[_to].add(_amount);
      Transfer(_from, _to, _amount);
      return true;
    } else {
      return false;
    }
  }

  //Approves a _spender an _amount of tokens to use
  function approve(address _spender, uint _amount) public returns (bool success) {
    allowed[msg.sender][_spender] = _amount;
    Approval(msg.sender, _spender, _amount);
    return true;
  }

  //Returns the remaining allowance of tokens granted to the _spender from the _owner
  function allowance(address _owner, address _spender) public view returns (uint remaining) { return allowed[_owner][_spender]; }
}
