/*
 * ===== SmartInject Injection Details =====
 * Function      : collectDevFees
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Modified External Call**: Replaced `owner.transfer(devFees)` with `owner.call.value(amount)("")` which allows unlimited gas forwarding and enables reentrancy attacks.
 * 
 * 2. **State Modification After External Call**: The critical vulnerability is that `devFees = 0` occurs AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1-N**: Normal users interact with `createCoin()` and `buyCoin()` functions over time, accumulating fees in the `devFees` state variable
 *    - **Transaction N+1**: Malicious owner contract calls `collectDevFees()` and reenters during the `.call()` execution
 *    - **Reentrant Calls**: Each reentrant call to `collectDevFees()` can drain the same `devFees` amount again since it's not reset to 0 until after the external call completes
 * 
 * 4. **Stateful Nature**: The vulnerability depends on:
 *    - Accumulated `devFees` from previous transactions (state persistence)
 *    - The owner being a malicious contract that can reenter
 *    - Multiple transactions to build up the fee pool before exploitation
 * 
 * 5. **Realistic Injection**: The change from `transfer()` to `call()` is a common pattern developers use when they need more gas or want to handle failures gracefully, making this a realistic vulnerability that could appear in production code.
 * 
 * **Exploitation Scenario**:
 * 1. Over multiple transactions, users create coins and buy coins, accumulating devFees
 * 2. Owner (malicious contract) calls `collectDevFees()`
 * 3. During the `call()` execution, the malicious owner contract reenters `collectDevFees()`
 * 4. Since `devFees` hasn't been reset to 0 yet, the reentrant call can drain the same amount again
 * 5. This can be repeated multiple times in a single transaction, draining accumulated fees
 * 
 * This creates a genuine multi-transaction vulnerability where the accumulated state from previous transactions enables the exploitation in subsequent transactions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    if (devFees > 0) {
        uint amount = devFees;
        (bool success, ) = owner.call.value(amount)("");
        require(success, "Transfer failed");
        devFees = 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function() public payable {}

}