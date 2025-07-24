/*
 * ===== SmartInject Injection Details =====
 * Function      : authoriseSale
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
 * This injection introduces a timestamp dependence vulnerability through time-based fee calculations that create a multi-transaction exploit scenario:
 * 
 * **Specific Changes Made:**
 * 1. Added `authorisedSaleTimestamps[x][y]` state variable to store authorization timestamps
 * 2. Introduced dynamic fee calculation based on time difference between authorizations
 * 3. Added 50% fee discount for re-authorizations within 1 hour (3600 seconds)
 * 4. Fee calculation now depends on `block.timestamp` and previous authorization timing
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker calls `authoriseSale()` with the full fee amount, establishing a timestamp baseline in `authorisedSaleTimestamps[x][y]`
 * 2. **Transaction 2 (Exploit)**: Within the same block or shortly after (manipulating block timestamp), attacker calls `authoriseSale()` again with only half the required fee amount. Due to the time-based discount logic, this succeeds even though the amount is insufficient for the normal fee
 * 3. **State Persistence**: The reduced fee authorization persists in contract state, allowing completion of an under-priced sale
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - **State Dependency**: The vulnerability requires a previous authorization timestamp to be stored in state (`authorisedSaleTimestamps[x][y] > 0`)
 * - **Time Accumulation**: The exploit relies on the time difference calculation between two separate function calls
 * - **Sequential Logic**: The fee discount only applies on subsequent calls after an initial timestamp is established
 * - **Miner Manipulation**: Miners can manipulate block timestamps across blocks to trigger the discount condition inappropriately
 * 
 * **Realistic Attack Vector:**
 * An attacker (potentially a miner) could manipulate block timestamps to consistently trigger the 50% fee discount, allowing them to authorize sales with insufficient fees. This creates an economic advantage and breaks the intended fee structure of the contract.
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
  mapping(uint => mapping(uint => uint)) authorisedSaleTimestamps;

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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Store authorization timestamp for time-based fee calculation
    uint authTimestamp = block.timestamp;
    
    // Dynamic fee calculation based on time since last sale
    uint baseFee = getSaleFee();
    uint timeSinceLastAuth = authTimestamp - authorisedSaleTimestamps[x][y];
    
    // Fee discount for quick re-authorizations (within 1 hour)
    uint fee = baseFee;
    if (authorisedSaleTimestamps[x][y] > 0 && timeSinceLastAuth < 3600) {
        fee = baseFee / 2; // 50% discount for quick re-authorization
    }
    
    require(amount >= fee);
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    authorisedSaleAddresses[x][y] = buyer;
    authorisedSalePrices[x][y] = amount;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    authorisedSaleTimestamps[x][y] = authTimestamp; // Store current timestamp
    
    return true;
}
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
