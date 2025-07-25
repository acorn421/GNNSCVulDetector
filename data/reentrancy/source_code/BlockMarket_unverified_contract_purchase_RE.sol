/*
 * ===== SmartInject Injection Details =====
 * Function      : purchase
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by moving critical state updates (share.holder, share.purchasePrice, stock.lastAction) to occur BEFORE external calls to previousHolder and dividend recipients. This creates a window where the contract state is inconsistent during external calls, allowing for multi-transaction exploitation patterns.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **State Update Reordering**: Moved the state updates (share.holder = msg.sender, share.purchasePrice = currentPrice, stock.lastAction = block.timestamp) to occur immediately after fee calculation and before the external calls to previousHolder and dividend recipients.
 * 
 * 2. **External Call Sequence**: The previousHolder.transfer() and dividend loop transfers now execute AFTER the state has been updated, creating a reentrancy window where the share ownership and price have changed but payments are still being processed.
 * 
 * 3. **Event Parameter Adjustment**: Modified the ShareSold event to use the original previousHolder variable instead of share.holder to maintain consistency with the original holder information.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Initial Purchase):**
 * - Attacker calls purchase() with a malicious contract as msg.sender
 * - State is updated early: share.holder becomes the attacker's contract
 * - During previousHolder.transfer(), attacker's contract receives control
 * - Attacker can observe that share ownership has changed but dividend payments haven't occurred yet
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker's contract, now identified as the new holder, can call purchase() again on the same or different shares
 * - Since share.holder was updated in Transaction 1, price calculations and dividend distributions may be based on the new state
 * - The attacker can potentially manipulate the dividend distribution or exploit price calculation inconsistencies
 * 
 * **Transaction 3+ (State Accumulation):**
 * - Repeated calls can accumulate state changes across multiple transactions
 * - The attacker can build up inconsistent state where ownership records, price history, and dividend payments become desynchronized
 * - Multiple shares across different stocks can be manipulated using the accumulated state inconsistencies
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Persistence**: The vulnerability depends on the persistent state changes (share.holder, share.purchasePrice) that remain between transactions
 * 2. **External Call Timing**: The reentrancy window only exists during the external calls, requiring the attacker to leverage this across multiple function invocations
 * 3. **Accumulated Inconsistencies**: The full exploitation potential is only realized when state inconsistencies accumulate across multiple purchase transactions
 * 4. **Dividend Dependency**: The dividend calculation system depends on the current state of all shares, which can only be manipulated effectively across multiple transactions
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world reentrancy patterns where state updates occur before external calls, enabling sophisticated multi-transaction exploits.
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

    stocks.push(
      Stock(
        _name,
        _priceIncrease == 0 ? 130 : _priceIncrease, // 30% by default
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // VULNERABILITY: Early state update creates window for reentrancy exploitation
    // Update share information before external calls to create inconsistent state
    share.holder = msg.sender;
    share.purchasePrice = currentPrice;
    stock.lastAction = block.timestamp;

    // payout the previous shareholder - external call after state change
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    previousHolder.transfer(SafeMath.sub(previousHolderShare, fee));

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // payout the dividends - external calls with accumulated state dependency
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      previousHolder,  // Use original holder in event
      msg.sender
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    );
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