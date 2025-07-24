/*
 * ===== SmartInject Injection Details =====
 * Function      : addStock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability that creates time-based market manipulation opportunities. The vulnerability introduces a time-based modifier system that adjusts the priceIncrease parameter based on the timing between consecutive stock additions. This creates a multi-transaction exploit where an attacker (or malicious miner) can manipulate block timestamps across multiple addStock calls to artificially inflate price increases for newly added stocks.
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added Time-Based Modifier Logic**: Introduced a `timeModifier` calculation that depends on the time difference between the current block.timestamp and the lastAction timestamp of the previously added stock.
 * 
 * 2. **State-Dependent Calculation**: The modifier calculation requires reading the state from previously added stocks (`stocks[stocks.length - 1].lastAction`), making it stateful and dependent on prior transactions.
 * 
 * 3. **Applied Modifier to Price Increase**: The `adjustedPriceIncrease` applies the time-based modifier to the stock's price increase rate, affecting future purchase prices.
 * 
 * **Multi-Transaction Exploitation:**
 * 
 * The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Add an initial stock to establish a baseline timestamp in the stocks array
 * 2. **Transaction 2+**: Add subsequent stocks with carefully timed block timestamps to trigger the rapid addition bonus (150% multiplier)
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - **State Dependency**: The vulnerability only activates when `stocks.length > 0`, requiring at least one prior stock addition
 * - **Timestamp Comparison**: The exploit depends on comparing current `block.timestamp` with the `lastAction` of the previously added stock
 * - **Accumulated Effect**: Each subsequent stock addition can benefit from the time-based modifier, creating cascading effects across multiple transactions
 * - **Cross-Function Impact**: The inflated `priceIncrease` values affect the `purchase()` function, where higher price increases lead to more expensive share purchases and larger profits for share sellers
 * 
 * **Realistic Attack Scenarios:**
 * 
 * 1. **Miner Manipulation**: A malicious miner could manipulate block timestamps to consistently trigger the rapid addition bonus when adding multiple stocks
 * 2. **Coordinated Timing**: An attacker could time their stock additions to exploit the time-based bonuses systematically
 * 3. **Market Manipulation**: By inflating price increases through timing manipulation, an attacker could create artificially profitable stocks that benefit them when shares are later purchased
 * 
 * This vulnerability is realistic because time-based business logic is common in financial contracts, and the dependency on block.timestamp for market timing decisions creates a practical attack vector.
 */
pragma solidity ^0.4.19;

/**
 * @title Ownable
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

/**
 * @title SafeMath Library
 */
library SafeMath {
  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title BlockMarketCore
 */
contract BlockMarket is Ownable {
  struct Stock {
    string  name;
    uint256 priceIncrease;
    uint256 dividendAmount;
    uint256 lastAction;
    uint256 dividendsPaid;
  }

  struct Share {
    address holder;
    uint256 purchasePrice;
  }

  Stock[] public stocks;
  Share[] public shares;
  mapping (uint256 => uint256[]) public stockShares;

  event CompanyListed(string company, uint256 basePrice);
  event DividendPaid(address shareholder, uint256 amount);
  event ShareSold(
    uint256 stockId,
    uint256 shareId,
    uint256 oldPrice,
    uint256 newPrice,
    address oldOwner,
    address newOwner
  );

  /**
   * @dev A fallback function to catch, uh... let's call them gifts.
   */
  function () payable public { }

  /**
   * @dev Adds a new stock to the game
   * @param _name the name of the stock (e.g. "Kodak")
   * @param _initialPrice the original cost of the stock's shares (in Wei)
   * @param _priceIncrease the amount by which the shares should increase upon sale (i.e. 120 = 20% increase)
   * @param _dividendAmount the amount of each purchase that should be split among dividend recipients
   * @param _numShares the number of shares of this stock available for purchase
   */
  function addStock(
    string  _name,
    uint256 _initialPrice,
    uint256 _priceIncrease,
    uint256 _dividendAmount,
    uint8   _numShares
  ) public onlyOwner returns (uint256 stockId) {
    stockId = stocks.length;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based modifier for price increase based on market timing
    uint256 timeModifier = 100;
    if (stocks.length > 0) {
      // Calculate time-based bonus/penalty based on last stock addition
      uint256 timeSinceLastStock = block.timestamp - stocks[stocks.length - 1].lastAction;
      
      // Rapid consecutive additions (< 1 hour) get bonus multiplier
      if (timeSinceLastStock < 3600) {
        timeModifier = 150; // 50% bonus for rapid additions
      }
      // Medium timing (1-24 hours) gets standard rate
      else if (timeSinceLastStock < 86400) {
        timeModifier = 100; // Standard rate
      }
      // Long gaps (> 24 hours) get penalty
      else {
        timeModifier = 75; // 25% penalty for delayed additions
      }
    }

    // Apply time-based modifier to price increase
    uint256 adjustedPriceIncrease = (_priceIncrease == 0 ? 130 : _priceIncrease) * timeModifier / 100;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    stocks.push(
      Stock(
        _name,
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        adjustedPriceIncrease,
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        _dividendAmount == 0 ? 110 : _dividendAmount, // 10% by default
        block.timestamp,
        0
      )
    );

    for(uint8 i = 0; i < _numShares; i++) {
      stockShares[stockId].push(shares.length);
      shares.push(Share(owner, _initialPrice));
    }

    CompanyListed(_name, _initialPrice);
  }

  /**
   * @dev Purchase a share from its current owner
   * @param _stockId the ID of the stock that owns the share
   * @param _shareId the ID of the specific share to purchase
   */
  function purchase(uint256 _stockId, uint256 _shareId) public payable {
    require(_stockId < stocks.length && _shareId < shares.length);

    // look up the assets
    Stock storage stock = stocks[_stockId];
    uint256[] storage sharesForStock = stockShares[_stockId];
    Share storage share = shares[sharesForStock[_shareId]];

    // look up the share's current holder
    address previousHolder = share.holder;

    // determine the current price for the share
    uint256 currentPrice = getPurchasePrice(
      share.purchasePrice,
      stock.priceIncrease
    );
    require(msg.value >= currentPrice);

    // return any excess payment
    if (msg.value > currentPrice) {
      msg.sender.transfer(SafeMath.sub(msg.value, currentPrice));
    }

    // calculate dividend holders' shares
    uint256 dividendPerRecipient = getDividendPayout(
      currentPrice,
      stock.dividendAmount,
      sharesForStock.length - 1
    );

    // calculate the previous owner's share
    uint256 previousHolderShare = SafeMath.sub(
      currentPrice,
      SafeMath.mul(dividendPerRecipient, sharesForStock.length - 1)
    );

    // calculate the transaction fee - 1/40 = 2.5% fee
    uint256 fee = SafeMath.div(previousHolderShare, 40);
    owner.transfer(fee);

    // payout the previous shareholder
    previousHolder.transfer(SafeMath.sub(previousHolderShare, fee));

    // payout the dividends
    for(uint8 i = 0; i < sharesForStock.length; i++) {
      if (i != _shareId) {
        shares[sharesForStock[i]].holder.transfer(dividendPerRecipient);
        stock.dividendsPaid = SafeMath.add(stock.dividendsPaid, dividendPerRecipient);
        DividendPaid(
          shares[sharesForStock[i]].holder,
          dividendPerRecipient
        );
      }
    }

    ShareSold(
      _stockId,
      _shareId,
      share.purchasePrice,
      currentPrice,
      share.holder,
      msg.sender
    );

    // update share information
    share.holder = msg.sender;
    share.purchasePrice = currentPrice;
    stock.lastAction = block.timestamp;
  }

  /**
   * @dev Calculates the current purchase price for the given stock share
   * @param _stockId the ID of the stock that owns the share
   * @param _shareId the ID of the specific share to purchase
   */
  function getCurrentPrice(
    uint256 _stockId,
    uint256 _shareId
  ) public view returns (uint256 currentPrice) {
    require(_stockId < stocks.length && _shareId < shares.length);
    currentPrice = SafeMath.div(
      SafeMath.mul(stocks[_stockId].priceIncrease, shares[_shareId].purchasePrice),
      100
    );
  }

  /**
   * @dev Calculates the current token owner's payout amount if the token sells
   * @param _currentPrice the current total sale price of the asset
   * @param _priceIncrease the percentage of price increase per sale
   */
  function getPurchasePrice(
    uint256 _currentPrice,
    uint256 _priceIncrease
  ) internal pure returns (uint256 currentPrice) {
    currentPrice = SafeMath.div(
      SafeMath.mul(_currentPrice, _priceIncrease),
      100
    );
  }

  /**
   * @dev Calculates the payout of each dividend recipient in the event of a share sale.
   * @param _purchasePrice the current total sale price of the asset
   * @param _stockDividend the percentage of the sale allocated for dividends
   * @param _numDividends the number of dividend holders to share the total dividend amount
   */
  function getDividendPayout(
    uint256 _purchasePrice,
    uint256 _stockDividend,
    uint256 _numDividends
  ) public pure returns (uint256 dividend) {
    uint256 dividendPerRecipient = SafeMath.sub(
      SafeMath.div(SafeMath.mul(_purchasePrice, _stockDividend), 100),
      _purchasePrice
    );
    dividend = SafeMath.div(dividendPerRecipient, _numDividends);
  }

  /**
  * @dev Fetches the number of stocks available
  */
  function getStockCount() public view returns (uint256) {
    return stocks.length;
  }

  /**
  * @dev Fetches the share IDs connected to the given stock
  * @param _stockId the ID of the stock to count shares of
  */
  function getStockShares(uint256 _stockId) public view returns (uint256[]) {
    return stockShares[_stockId];
  }

  /**
   * @dev Transfers a set amount of ETH from the contract to the specified address
   * @notice Proceeds are paid out right away, but the contract might receive unexpected funds
   */
  function withdraw(uint256 _amount, address _destination) public onlyOwner {
    require(_destination != address(0));
    require(_amount <= this.balance);
    _destination.transfer(_amount == 0 ? this.balance : _amount);
  }
}