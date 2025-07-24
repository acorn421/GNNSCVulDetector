/*
 * ===== SmartInject Injection Details =====
 * Function      : completeSale
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing time-based sale windows and dynamic fee calculations that depend on block.timestamp. The vulnerability requires multiple transactions because:
 * 
 * 1. **Sale Authorization Phase** (Transaction 1): When `authoriseSale()` is called, it establishes the sale but doesn't set timing constraints directly. The timing is calculated based on the plot's `saleCount` history.
 * 
 * 2. **Timing Window Exploitation** (Transaction 2+): The `completeSale()` function now enforces a 1-hour minimum wait and 24-hour maximum window based on a calculated timestamp derived from the plot's sale history. Miners can manipulate `block.timestamp` to:
 *    - Bypass the minimum wait time requirement
 *    - Extend the validity window when beneficial
 *    - Manipulate the dynamic fee calculation that depends on time elapsed
 * 
 * 3. **Dynamic Fee Manipulation**: The fee calculation uses `timeElapsed` derived from `block.timestamp`, creating opportunities for miners to reduce fees by manipulating timestamps. The fee can vary significantly (0-23% additional) based on the "hour multiplier."
 * 
 * 4. **State Accumulation**: The vulnerability leverages the `saleCount` field to create historical timestamp dependencies. Every 10th sale triggers terrain updates based on timestamp XOR operations, creating additional manipulation vectors.
 * 
 * **Multi-Transaction Requirement**: The vulnerability cannot be exploited in a single transaction because:
 * - It requires prior sale authorization (separate transaction)
 * - The timing calculations depend on historical state (`saleCount`)
 * - Miners need time between transactions to manipulate timestamp conditions
 * - The exploitation requires observing and timing multiple sale attempts to maximize fee reduction benefits
 * 
 * **Exploitation Scenario**:
 * 1. Attacker observes a high-value plot sale authorization
 * 2. Attacker waits for optimal timestamp conditions (low fee multiplier hour)
 * 3. Miner collaborates to set favorable `block.timestamp` for minimum fees
 * 4. Attack executes `completeSale()` with significantly reduced fees
 * 5. For every 10th sale, additional terrain manipulation occurs based on timestamp
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
    // Load values only when needed to avoid stack too deep
    address seller = plots[x][y].owner;
    {
      address _authorisedSaleAddress = authorisedSaleAddresses[x][y];
      uint _authorisedSalePrice = authorisedSalePrices[x][y];
      require(_authorisedSaleAddress != 0x0);
      require(_authorisedSaleAddress == buyer);
      require(_authorisedSalePrice == msg.value);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

    // Timestamp-dependent sale window validation
    Plot storage plot = plots[x][y];
    uint saleAuthTime = plot.saleCount > 0 ? (block.timestamp - (plot.saleCount * 3600)) : block.timestamp;
    require(block.timestamp >= saleAuthTime + 3600);
    require(block.timestamp <= saleAuthTime + 86400);

    uint price = msg.value;

    // Time-based dynamic fee calculation using stored timestamp
    uint baseFee = getSaleFee();
    uint timeElapsed = block.timestamp - saleAuthTime;
    uint timeBonusMultiplier = (timeElapsed / 3600) % 24; // 0-23 hour multiplier
    uint dynamicFee = baseFee + (baseFee * timeBonusMultiplier / 100);
    uint fee = dynamicFee;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    uint forSeller = price - fee;
    // address seller = plot.owner;  // Already defined above
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

    // Store timestamp for future calculations
    plot.saleCount += 1;
    if (plot.saleCount % 10 == 0) {
        // Every 10th sale gets timestamp-based terrain update
        plot.terrain = bytes32(block.timestamp ^ uint256(plot.terrain));
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    plot.owner = buyer;
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
