/*
 * ===== SmartInject Injection Details =====
 * Function      : buyPlot
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by implementing a payment accumulation system that requires multiple transactions to complete a purchase. The vulnerability exploits the fact that:
 * 
 * 1. **State Persistence**: Payment tracking state (accumulatedPayments, paymentCount) persists between transactions
 * 2. **Multi-Transaction Flow**: First transaction initializes payment tracking, subsequent transactions complete the purchase
 * 3. **Reentrancy Window**: External calls are made before critical state updates (plot ownership assignment)
 * 4. **Exploitation Path**: 
 *    - Transaction 1: Attacker calls buyPlot() which triggers onPaymentReceived callback
 *    - During callback, attacker can call buyPlot() again since plot is still not owned
 *    - Transaction 2: Attacker calls buyPlot() again, triggering onPurchaseComplete callback
 *    - During this callback, attacker can manipulate state or call other functions while plot ownership is still being processed
 *    - The accumulated payment state allows the attacker to potentially claim multiple plots or manipulate the payment system
 * 
 * The vulnerability requires multiple transactions because the payment accumulation logic only triggers the full purchase flow after the first payment is recorded, and the external calls provide reentrancy opportunities at different stages of the multi-transaction process.
 */
pragma solidity ^0.4.18;

contract Terrus {
  event PlotSale(
    uint indexed _x,
    uint indexed _y,
    address _from,
    address indexed _to,
    uint _price,
    bool _gift
  );

  event PlotTerrainUpdate(
    uint indexed _x,
    uint indexed _y,
    address indexed _by,
    uint _price,
    bytes32 _newTerrain
  );

  event Withdrawal(
    address _recipient,
    uint _amount
  );

  struct Plot {
    bool owned;
    address owner;
    uint x;
    uint y;
    bytes32 terrain;
    uint saleCount;
  }
  mapping(uint => mapping(uint => Plot)) plots;

  address owner;

  mapping(uint => mapping(uint => address)) authorisedSaleAddresses;
  mapping(uint => mapping(uint => uint)) authorisedSalePrices;

  // === Added missing state variables for reentrancy pattern ===
  mapping(uint => mapping(uint => mapping(address => uint))) accumulatedPayments;
  mapping(uint => mapping(uint => mapping(address => uint))) paymentCount;

  // Constructor
  function Terrus() public {
    owner = msg.sender;
  }

  // Modifiers
  modifier ownerOnly() {
    require(msg.sender == owner);
    _;
  }

  modifier validNewTerrain(uint x, uint y, bytes32 newTerrain) {
    // TODO
    _;
  }

  modifier xyBounded(uint x, uint y) {
    require(x < 1000);
    require(y < 1000);
    _;
  }

  // Public
  function authoriseSale(uint x, uint y, address buyer, uint amount) public returns (bool) {
    Plot memory plot = plots[x][y];
    require(plot.owned);
    require(plot.owner == msg.sender);
    uint fee = getSaleFee();
    require(amount >= fee);
    authorisedSaleAddresses[x][y] = buyer;
    authorisedSalePrices[x][y] = amount;
    return true;
  }

  function buyPlot(uint x, uint y) xyBounded(x, y) public payable returns (bool) {
    require(!plots[x][y].owned);
    uint price = getPlotPrice();
    require(price == msg.value);
    address buyer = msg.sender;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Track accumulated payments for multi-transaction purchases
    if (accumulatedPayments[x][y][buyer] == 0) {
        accumulatedPayments[x][y][buyer] = msg.value;
        paymentCount[x][y][buyer] = 1;
        // Notify external contract about payment (potential reentrancy point)
        uint length;
        assembly {
            length := extcodesize(buyer)
        }
        if (length > 0) {
            buyer.call(bytes4(keccak256("onPaymentReceived(uint256,uint256,uint256)")), x, y, msg.value);
        }
        return true;
    }
    
    // Complete purchase if this is a subsequent payment
    accumulatedPayments[x][y][buyer] += msg.value;
    paymentCount[x][y][buyer]++;
    
    // External call before state update - classic reentrancy pattern
    uint length2;
    assembly {
        length2 := extcodesize(buyer)
    }
    if (length2 > 0) {
        buyer.call(bytes4(keccak256("onPurchaseComplete(uint256,uint256,uint256)")), x, y, accumulatedPayments[x][y][buyer]);
    }
    
    // State update occurs after external call
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    plots[x][y] = Plot({
      owned: true,
      owner: buyer,
      x: x,
      y: y,
      terrain: getInitialTerrain(x, y),
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      saleCount: paymentCount[x][y][buyer]
    });
    
    // Clear payment tracking
    accumulatedPayments[x][y][buyer] = 0;
    paymentCount[x][y][buyer] = 0;
    
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    PlotSale(x, y, 0x0, buyer, price, false);
    return true;
  }

  function completeSale(uint x, uint y) public payable returns (bool) {
    address buyer = msg.sender;
    require(authorisedSaleAddresses[x][y] != 0x0);
    require(authorisedSaleAddresses[x][y] == buyer);
    require(authorisedSalePrices[x][y] == msg.value);
    uint price = msg.value;
    uint fee = getSaleFee();
    uint forSeller = price - fee;
    Plot storage plot = plots[x][y];
    address seller = plot.owner;
    plot.owner = buyer;
    plot.saleCount += 1;
    authorisedSaleAddresses[x][y] = 0x0;
    authorisedSalePrices[x][y] = 0;
    seller.transfer(forSeller);
    PlotSale(x, y, seller, buyer, price, false);
    return true;
  }

  function deAuthoriseSale(uint x, uint y) public returns (bool) {
    Plot storage plot = plots[x][y];
    require(plot.owned);
    require(plot.owner == msg.sender);
    authorisedSaleAddresses[x][y] = 0x0;
    authorisedSalePrices[x][y] = 0;
    return true;
  }

  function getInitialTerrain(uint x, uint y) public pure returns (bytes32) {
    return sha256(x, y);
  }

  function getOwner() public view returns (address) {
    return owner;
  }

  function getPlot(uint x, uint y) public xyBounded(x, y) view returns (bool owned, address plotOwner, uint plotX, uint plotY, bytes32 plotTerrain) {
    Plot memory plot = plots[x][y];
    bytes32 terrain = plot.owned ? plot.terrain : getInitialTerrain(x, y);
    return (plot.owned, plot.owner, x, y, terrain);
  }

  function getPlotPrice() public pure returns (uint) {
    return 0.01 ether;
  }

  function getSaleFee() public pure returns (uint) {
    return 0.01 ether;
  }

  function getSetNewTerrainPrice(uint x, uint y, bytes32 newTerrain) public xyBounded(x, y) validNewTerrain(x, y, newTerrain) view returns (uint) {
    Plot memory plot = plots[x][y];
    bytes32 currentTerrain = plot.owned ? plot.terrain : getInitialTerrain(x, y);
    uint changed = 0;
    for (uint i = 0; i < 32; i++) {
      if (newTerrain[i] != currentTerrain[i]) {
        changed += 1;
      }
    }
    uint price = changed * (0.01 ether);
    require(price >= 0);
    return price;
  }

  function giftPlot(uint x, uint y, address recipient) public ownerOnly xyBounded(x, y) returns (bool) {
    require(!plots[x][y].owned);
    plots[x][y] = Plot({
      owned: true,
      owner: recipient,
      x: x,
      y: y,
      terrain: getInitialTerrain(x, y),
      saleCount: 1
    });
    PlotSale(x, y, 0x0, recipient, 0, true);
    return true;
  }

  function ping() public pure returns (bytes4) {
    return "pong";
  }

  // TODO TEST
  function setNewTerrain(uint x, uint y, bytes32 newTerrain) public xyBounded(x, y) validNewTerrain(x, y, newTerrain) payable returns (bool) {
    Plot storage plot = plots[x][y];
    require(plot.owned);
    require(plot.owner == msg.sender);
    uint setPrice = getSetNewTerrainPrice(x, y, newTerrain);
    require(msg.value == setPrice);
    plot.terrain = newTerrain;
    PlotTerrainUpdate(x, y, msg.sender, msg.value, newTerrain);
    return true;
  }

  function setOwner(address newOwner) public ownerOnly returns (bool) {
    owner = newOwner;
    return true;
  }

  function withdrawEther(uint amount) public ownerOnly returns (bool) {
    require(this.balance >= amount);
    address recipient = msg.sender;
    recipient.transfer(amount);
    Withdrawal(recipient, amount);
    return true;
  }
}
