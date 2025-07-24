/*
 * ===== SmartInject Injection Details =====
 * Function      : createCoin
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled "CoinRegistry" contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Setup Transaction**: Attacker deploys malicious CoinRegistry contract and calls createCoin with ID 100, paying the current newCoinFee (e.g., 0.005 ether)
 * 
 * 2. **Reentrancy Transaction**: During the external call to validateCoinCreation, the malicious contract re-enters createCoin with ID 101 before the first call completes its state updates
 * 
 * 3. **State Manipulation**: The reentrant call sees the old newCoinFee value and can create additional coins at the lower fee, bypassing the fee increase mechanism
 * 
 * 4. **Exploitation Chain**: Multiple reentrant calls can be chained to create numerous coins while only paying the original fee, exploiting the accumulated state changes
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent state of `newCoinFee` that accumulates across multiple coin creations
 * - Each successful createCoin call increases `newCoinFee` for subsequent calls
 * - The exploit requires setting up the malicious registry contract first, then triggering the reentrancy
 * - The state inconsistency only becomes valuable when exploited across multiple coin creations
 * - Single-transaction exploitation is prevented by the requirement to deploy and interact with the external registry
 * 
 * **Realistic Scenario:**
 * A legitimate-looking feature where coins are validated against an external registry service, but the external call occurs before state updates, violating the Checks-Effects-Interactions pattern and enabling multi-transaction reentrancy exploitation of the fee mechanism.
 */
pragma solidity ^0.4.23;

contract CoinRegistry {
    function validateCoinCreation(uint16, string) public returns (bool) {}
}

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // External call to coin registry service for validation
    CoinRegistry registry = CoinRegistry(msg.sender);
    bool registrationSuccess = registry.validateCoinCreation(id, name);
    require(registrationSuccess);
    
    // State updates moved after external call - VULNERABILITY
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    devFees += msg.value - defaultCoinPrice;
    coins[id].exists = true;
    coins[id].name = name;
    coins[id].price = defaultCoinPrice;
    coins[id].marketValue = defaultCoinPrice;
    coins[id].investors.push(msg.sender);
    coinIds.push(id);
    newCoinFee += newCoinFeeIncrease;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
