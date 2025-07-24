/*
 * ===== SmartInject Injection Details =====
 * Function      : collectDevFees
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based withdrawal controls that rely on block.timestamp for critical logic. The vulnerability requires multiple state variables (lastWithdrawal, dailyLimitReset, dailyWithdrawnAmount) that persist between transactions and create exploitable timing dependencies.
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added State Variables** (assumed to be declared at contract level):
 *    - `lastWithdrawal`: Tracks timestamp of last withdrawal
 *    - `dailyLimitReset`: Tracks when daily limit was last reset
 *    - `dailyWithdrawnAmount`: Tracks amount withdrawn in current day
 * 
 * 2. **Time-Based Cooldown Logic**: 
 *    - Requires 1 hour cooldown between withdrawals using `block.timestamp >= lastWithdrawal + 1 hours`
 *    - State persists between transactions, enabling multi-transaction exploitation
 * 
 * 3. **Daily Withdrawal Limits**:
 *    - Implements 24-hour rolling limit reset using `block.timestamp >= dailyLimitReset + 24 hours`
 *    - Tracks cumulative withdrawals in `dailyWithdrawnAmount`
 * 
 * 4. **Time-Based Bonus System**:
 *    - Provides 10% bonus if withdrawn within 1 hour of limit reset
 *    - Creates additional timestamp-dependent incentive for exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Owner calls `collectDevFees()` - initializes timing state, sets `lastWithdrawal = block.timestamp`
 * 2. **Wait Period**: Must wait for cooldown period (1 hour) - cannot exploit immediately
 * 3. **Transaction 2**: Miner manipulates `block.timestamp` to bypass cooldown or trigger bonus conditions
 * 4. **Transaction 3**: Additional calls can exploit timing windows for bonus payments or reset manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **Cooldown Enforcement**: Cannot withdraw multiple times in single transaction due to 1-hour cooldown
 * - **State Accumulation**: Daily withdrawal tracking requires persistent state across calls
 * - **Timing Manipulation**: Miners need multiple blocks to manipulate timestamps effectively
 * - **Bonus Exploitation**: Time-based bonuses require strategic timing across multiple transactions
 * 
 * **Realistic Vulnerability**: This mimics real-world DeFi protocols that implement withdrawal limits and time-based controls, making it a credible timestamp dependence vulnerability that requires stateful, multi-transaction exploitation.
 */
pragma solidity ^0.4.23;

contract PumpAndDump {

  address owner;
  uint newCoinFee = 0.005 ether;
  uint newCoinFeeIncrease = 0.001 ether;
  uint defaultCoinPrice = 0.001 ether;
  uint coinPriceIncrease = 0.0001 ether;
  uint devFees = 0;
  uint16[] coinIds;

  // ADDED for collectDevFees timestamp tracking
  uint public lastWithdrawal = 0;
  uint public dailyLimitReset = 0;
  uint public dailyWithdrawnAmount = 0;

  struct Coin {
    bool exists;
    string name;
    uint price;
    uint marketValue;
    address[] investors;
  }

  mapping (uint16 => Coin) coins;

  constructor() public {
    owner = msg.sender;
  }

  function kill() external {
    require(msg.sender == owner);
    selfdestruct(owner);
  }

  function getNewCoinFee() public constant returns (uint) {
    return newCoinFee;
  }

  function isCoinIdUnique(uint16 newId) private constant returns (bool) {
    for (uint i = 0; i < coinIds.length; i++) {
      if (coinIds[i] == newId) {
        return false;
      }
    }
    return true;
  }


  function createCoin(uint16 id, string name) public payable {
    require(msg.value >= newCoinFee);
    require(id < 17576); // 26*26*26
    require(bytes(name).length > 0);
    require(isCoinIdUnique(id));
    devFees += msg.value - defaultCoinPrice;
    coins[id].exists = true;
    coins[id].name = name;
    coins[id].price = defaultCoinPrice;
    coins[id].marketValue = defaultCoinPrice;
    coins[id].investors.push(msg.sender);
    coinIds.push(id);
    newCoinFee += newCoinFeeIncrease;
  }

  function getCoinIds() public view returns (uint16[]) {
    return coinIds;
  }

  function getCoinInfoFromId(uint16 coinId) public view returns (string, uint, uint, address[]) {
    return (
      coins[coinId].name,
      coins[coinId].price,
      coins[coinId].marketValue,
      coins[coinId].investors
    );
  }

  function getUserCoinMarketValue(uint16 coinId, uint userIndex) private view returns (uint) {
      uint numInvestors = coins[coinId].investors.length;
      // If this is the most recent investor
      if (numInvestors == userIndex + 1) {
        return coins[coinId].price;
      } else {
        uint numShares = (numInvestors * (numInvestors + 1)) / 2;
        return ((numInvestors - userIndex) * coins[coinId].marketValue) / numShares;
      }
  }

  function isSenderInvestor(address sender, address[] investors) private pure returns (bool) {
    for (uint i = 0; i < investors.length; i++) {
      if (investors[i] == sender) {
        return true;
      }
    }
    return false;
  }

  function buyCoin(uint16 coinId) public payable {
    require(msg.value >= coins[coinId].price);
    require(coins[coinId].exists);
    require(!isSenderInvestor(msg.sender, coins[coinId].investors));
    coins[coinId].investors.push(msg.sender);
    uint amount = (msg.value * 99) / 100;
    devFees += msg.value - amount;
    coins[coinId].marketValue += amount;
    coins[coinId].price += coinPriceIncrease;
  }

  function payAndRemoveInvestor(uint16 coinId, uint investorIndex) private {
    uint value = getUserCoinMarketValue(coinId, investorIndex);
    coins[coinId].investors[investorIndex].transfer(value);
    coins[coinId].price -= coinPriceIncrease;
    coins[coinId].marketValue -= value;
    if (coins[coinId].investors.length == 1) {
      delete coins[coinId].investors[0];
    } else {
      uint secondLastIndex = coins[coinId].investors.length - 1;
      for (uint j = investorIndex; j < secondLastIndex; j++) {
        coins[coinId].investors[j] = coins[coinId].investors[j - 1];
      }
    }
    coins[coinId].investors.length -= 1;
  }

  function sellCoin(uint16 coinId) public {
    bool senderIsInvestor = false;
    uint investorIndex = 0;
    require(coins[coinId].exists);
    for (uint i = 0; i < coins[coinId].investors.length; i++) {
      if (coins[coinId].investors[i] == msg.sender) {
        senderIsInvestor = true;
        investorIndex = i;
        break;
      }
    }
    require(senderIsInvestor);
    payAndRemoveInvestor(coinId, investorIndex);
  }

  function getDevFees() public view returns (uint) {
    require(msg.sender == owner);
    return devFees;
  }

  function collectDevFees() public {
    require(msg.sender == owner);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Initialize withdrawal tracking on first call
    if (lastWithdrawal == 0) {
        lastWithdrawal = block.timestamp;
    }
    
    // Reset daily withdrawal limit if 24 hours have passed
    if (block.timestamp >= dailyLimitReset + 24 hours) {
        dailyWithdrawnAmount = 0;
        dailyLimitReset = block.timestamp;
    }
    
    // Enforce 1 hour cooldown between withdrawals
    require(block.timestamp >= lastWithdrawal + 1 hours);
    
    // Enforce daily withdrawal limit of 1 ether
    require(dailyWithdrawnAmount + devFees <= 1 ether);
    
    // Apply time-based bonus: 10% bonus if withdrawn within 1 hour of limit reset
    uint withdrawalAmount = devFees;
    if (block.timestamp <= dailyLimitReset + 1 hours) {
        withdrawalAmount = (devFees * 110) / 100; // 10% bonus
    }
    
    owner.transfer(withdrawalAmount);
    dailyWithdrawnAmount += withdrawalAmount;
    lastWithdrawal = block.timestamp;
    devFees = 0;
  }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  function() public payable {}

}