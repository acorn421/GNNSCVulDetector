/*
 * ===== SmartInject Injection Details =====
 * Function      : createCoin
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
 * Introduced timestamp dependence vulnerability through dynamic fee calculation based on block.timestamp with stateful accumulation. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Dynamic Time-Based Pricing**: Fee calculation uses `(block.timestamp % 3600) / 60` creating predictable patterns miners can exploit
 * 2. **Stateful Timestamp Storage**: Each coin stores `creationTime` creating persistent state for future calculations
 * 3. **Multi-Transaction Rapid Creation Bonus**: 20% fee reduction for coins created within 5 minutes of previous coin, exploitable through timestamp manipulation across transactions
 * 4. **Accumulated State Dependency**: Each new coin creation depends on the stored timestamp of the previously created coin
 * 
 * **Multi-Transaction Exploitation Path**:
 * - Transaction 1: Create initial coin at strategically chosen timestamp
 * - Transaction 2+: Exploit stored timestamp and timing patterns to get fee reductions and favorable pricing
 * - Miners can manipulate block.timestamp across multiple blocks to maximize benefits
 * 
 * The vulnerability cannot be exploited in a single transaction as it requires the persistent state from previous coin creations and accumulated timing patterns.
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

  struct Coin {
    bool exists;
    string name;
    uint price;
    uint marketValue;
    address[] investors;
    uint creationTime; // Added this field
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Timestamp-based dynamic pricing with state accumulation
    uint timeFactor = (block.timestamp % 3600) / 60; // 0-59 based on minutes in hour
    uint dynamicFee = newCoinFee + (timeFactor * newCoinFeeIncrease / 10);
    
    // Store timestamp for future fee calculations - creates stateful dependency
    if (coinIds.length > 0) {
        uint lastCoinId = coinIds[coinIds.length - 1];
        uint timeDiff = block.timestamp - coins[uint16(lastCoinId)].creationTime;
        if (timeDiff < 300) { // Less than 5 minutes
            // Rapid creation bonus reduces fee but creates exploitable pattern
            dynamicFee = dynamicFee * 80 / 100;
        }
    }
    
    require(msg.value >= dynamicFee);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    devFees += msg.value - defaultCoinPrice;
    coins[id].exists = true;
    coins[id].name = name;
    coins[id].price = defaultCoinPrice;
    coins[id].marketValue = defaultCoinPrice;
    coins[id].investors.push(msg.sender);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    coins[id].creationTime = block.timestamp; // Store creation timestamp
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    owner.transfer(devFees);
    devFees = 0;
  }

  function() public payable {}

}
