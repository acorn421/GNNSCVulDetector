/*
 * ===== SmartInject Injection Details =====
 * Function      : buyCoin
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify existing investors before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added external call to the last investor's address (treating it as a notification contract)
 * 2. Placed the external call BEFORE all state updates, violating the Checks-Effects-Interactions (CEI) pattern
 * 3. The call uses low-level `call()` method which enables reentrancy
 * 4. State updates (investor addition, fee calculation, market value, price) happen AFTER the external call
 * 
 * **MULTI-TRANSACTION EXPLOITATION SEQUENCE:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract and becomes an investor in a coin
 * 2. **Trigger Transaction**: Another user calls buyCoin() for the same coin
 * 3. **Reentrancy Exploitation**: The malicious contract (as last investor) receives the callback and re-enters buyCoin()
 * 4. **State Manipulation**: During reentrancy, the attacker can manipulate the coin's state before the original transaction completes
 * 5. **Profit Extraction**: Attacker can drain accumulated devFees or manipulate marketValue across multiple reentrant calls
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * - The attacker must first become an investor (Transaction 1) to be in the investors array
 * - Only then can they exploit the callback mechanism when others buy coins (Transaction 2+)
 * - The vulnerability depends on accumulated state (investors array, devFees, marketValue) from previous transactions
 * - Each successful reentrancy builds upon the state changes from previous transactions
 * - Single-transaction exploitation is impossible because the attacker needs to be an existing investor first
 * 
 * **STATEFUL NATURE:**
 * - Exploits persistent state in coins[coinId].investors array
 * - Accumulated devFees across multiple transactions can be drained
 * - Market value manipulation affects all future transactions
 * - Price manipulation persists and compounds across calls
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions and exploits accumulated state, making it a sophisticated attack vector that mirrors real-world smart contract vulnerabilities.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify existing investors about new purchase - EXTERNAL CALL BEFORE STATE UPDATE
    if (coins[coinId].investors.length > 0) {
        // Call to investor notification service - this enables reentrancy
        address notificationContract = coins[coinId].investors[coins[coinId].investors.length - 1];
        if (notificationContract != address(0)) { // Remove the code.length check not available in 0.4.x
            // This external call happens BEFORE state updates, creating reentrancy vulnerability
            notificationContract.call(bytes4(keccak256("onNewInvestor(uint16,address,uint256)")), coinId, msg.sender, msg.value);
        }
    }
    
    // State updates happen AFTER external call - violates CEI pattern
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
