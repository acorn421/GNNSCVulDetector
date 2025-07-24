/*
 * ===== SmartInject Injection Details =====
 * Function      : deAuthoriseSale
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
 * Introduced a timestamp dependence vulnerability that requires multiple transactions to complete deauthorization. The vulnerability uses block.timestamp for critical timing logic and creates a stateful deauthorization process. The flaw allows miners to manipulate timestamps to control when deauthorizations can occur, potentially blocking legitimate deauthorization attempts or enabling unauthorized timing manipulation. This requires the addition of a new state mapping 'mapping(uint => mapping(uint => uint256)) deauthTimestamps;' to track deauthorization timing states across transactions.
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

  // Added missing mapping for deauthTimestamps
  mapping(uint => mapping(uint => uint256)) deauthTimestamps;

  // Constructor
  constructor() public {
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Create a timestamp-based deauthorization window
    uint256 currentTime = block.timestamp;
    uint256 deauthWindow = currentTime + (currentTime % 300); // Variable window based on timestamp modulo
    
    // Store deauthorization timing state for multi-transaction vulnerability
    if (deauthTimestamps[x][y] == 0) {
        // First deauthorization attempt - store timestamp
        deauthTimestamps[x][y] = deauthWindow;
        return false; // Require second call to complete
    } else {
        // Second call - check if timing window allows deauthorization
        if (block.timestamp >= deauthTimestamps[x][y] && 
            block.timestamp <= deauthTimestamps[x][y] + 60) { // 60 second execution window
            
            authorisedSaleAddresses[x][y] = 0x0;
            authorisedSalePrices[x][y] = 0;
            deauthTimestamps[x][y] = 0; // Reset for future use
            return true;
        } else {
            // Reset if outside window, forcing new deauth sequence
            deauthTimestamps[x][y] = 0;
            return false;
        }
    }
}
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
