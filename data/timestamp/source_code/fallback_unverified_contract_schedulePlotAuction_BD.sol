/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePlotAuction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction auction system. The vulnerability requires multiple transactions to exploit: 1) First, an auction must be scheduled using schedulePlotAuction(), 2) Then bidders place bids using bidOnPlot(), 3) Finally, the auction is finalized with finalizeAuction(). The vulnerability lies in the reliance on block.timestamp for auction timing, which can be manipulated by miners within certain bounds. Miners could potentially extend or shorten auction durations by up to ~900 seconds, allowing them to either prevent late bids or allow additional time for their own bids. The state persists across multiple transactions through the auction mappings, making this a stateful, multi-transaction vulnerability.
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

  event AuctionScheduled(uint indexed x, uint indexed y, uint endTime);
  event BidPlaced(uint indexed x, uint indexed y, address bidder, uint amount);
  event AuctionEnded(uint indexed x, uint indexed y, address winner, uint amount);

  struct Plot {
    bool owned;
    address owner;
    uint x;
    uint y;
    bytes32 terrain;
    uint saleCount;
  }

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Auction system for plots
  mapping(uint => mapping(uint => uint)) auctionEndTimes;
  mapping(uint => mapping(uint => uint)) auctionHighestBids;
  mapping(uint => mapping(uint => address)) auctionHighestBidders;
  mapping(uint => mapping(uint => bool)) auctionActive;

  function schedulePlotAuction(uint x, uint y, uint durationInBlocks) public xyBounded(x, y) returns (bool) {
    Plot storage plot = plots[x][y];
    require(plot.owned);
    require(plot.owner == msg.sender);
    require(!auctionActive[x][y]);
    
    // Vulnerable: Uses block.timestamp which can be manipulated by miners
    uint endTime = block.timestamp + (durationInBlocks * 15); // Assuming 15 second blocks
    auctionEndTimes[x][y] = endTime;
    auctionActive[x][y] = true;
    auctionHighestBids[x][y] = 0;
    auctionHighestBidders[x][y] = 0x0;
    
    AuctionScheduled(x, y, endTime);
    return true;
  }

  function bidOnPlot(uint x, uint y) public xyBounded(x, y) payable returns (bool) {
    require(auctionActive[x][y]);
    // Vulnerable: Relies on block.timestamp for auction timing
    require(block.timestamp < auctionEndTimes[x][y]);
    require(msg.value > auctionHighestBids[x][y]);
    
    // Refund previous highest bidder
    if (auctionHighestBidders[x][y] != 0x0) {
      auctionHighestBidders[x][y].transfer(auctionHighestBids[x][y]);
    }
    
    auctionHighestBids[x][y] = msg.value;
    auctionHighestBidders[x][y] = msg.sender;
    
    BidPlaced(x, y, msg.sender, msg.value);
    return true;
  }

  function finalizeAuction(uint x, uint y) public xyBounded(x, y) returns (bool) {
    require(auctionActive[x][y]);
    // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
    require(block.timestamp >= auctionEndTimes[x][y]);
    
    Plot storage plot = plots[x][y];
    address winner = auctionHighestBidders[x][y];
    uint winningBid = auctionHighestBids[x][y];
    
    if (winner != 0x0) {
      // Transfer plot ownership
      address previousOwner = plot.owner;
      plot.owner = winner;
      plot.saleCount += 1;
      
      // Pay previous owner (minus fee)
      uint fee = getSaleFee();
      uint forSeller = winningBid > fee ? winningBid - fee : 0;
      if (forSeller > 0) {
        previousOwner.transfer(forSeller);
      }
      
      PlotSale(x, y, previousOwner, winner, winningBid, false);
      AuctionEnded(x, y, winner, winningBid);
    }
    
    // Reset auction state
    auctionActive[x][y] = false;
    auctionEndTimes[x][y] = 0;
    auctionHighestBids[x][y] = 0;
    auctionHighestBidders[x][y] = 0x0;
    
    return true;
  }
  // === END FALLBACK INJECTION ===

  mapping(uint => mapping(uint => Plot)) plots;

  address owner;

  mapping(uint => mapping(uint => address)) authorisedSaleAddresses;
  mapping(uint => mapping(uint => uint)) authorisedSalePrices;

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
    plots[x][y] = Plot({
      owned: true,
      owner: buyer,
      x: x,
      y: y,
      terrain: getInitialTerrain(x, y),
      saleCount: 1
    });
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
