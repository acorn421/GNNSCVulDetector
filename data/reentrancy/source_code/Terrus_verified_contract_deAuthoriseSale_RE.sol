/*
 * ===== SmartInject Injection Details =====
 * Function      : deAuthoriseSale
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
 * **Stateful Multi-Transaction Reentrancy Vulnerability Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `authorizedBuyer.call()` before state updates
 * - The call notifies the authorized buyer about sale cancellation
 * - State modifications (`authorisedSaleAddresses[x][y] = 0x0` and `authorisedSalePrices[x][y] = 0`) occur AFTER the external call
 * - Used low-level `.call()` which allows reentrancy without throwing on failure
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker creates a malicious contract and gets it authorized as a buyer for a plot via `authoriseSale()`
 * - This sets `authorisedSaleAddresses[x][y] = attackerContract`
 * - The malicious contract is now in the authorized buyer position
 * 
 * **Transaction 2 (Reentrancy Attack):**
 * - Plot owner calls `deAuthoriseSale(x, y)` to cancel the sale
 * - Function calls `attackerContract.onSaleCancelled(x, y)` 
 * - **Reentrancy occurs here:** Malicious contract calls back into `completeSale(x, y)` while state is still inconsistent
 * - At this point, `authorisedSaleAddresses[x][y]` still contains the attacker's address (not yet cleared)
 * - The attacker can complete the sale at the original authorized price before deauthorization completes
 * - After reentrancy, the original `deAuthoriseSale` continues and clears the authorization (too late)
 * 
 * **Transaction 3+ (State Exploitation):**
 * - The attacker has now acquired the plot through the reentrant call
 * - The authorization state has been cleared, but the ownership transfer has already occurred
 * - Subsequent transactions can exploit the fact that the plot was acquired through this race condition
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability depends on the persistent state from Transaction 1 (authorized buyer setup)
 * - Without the prior authorization, the external call in `deAuthoriseSale` wouldn't occur
 * - The attack requires this accumulated state from previous transactions
 * 
 * **Temporal Separation:**
 * - Transaction 1 must complete to establish the authorized buyer state
 * - Transaction 2 exploits the window between external call and state update
 * - The vulnerability cannot be triggered in a single transaction because the authorization must already exist
 * 
 * **Cross-Function State Exploitation:**
 * - The reentrancy allows calling `completeSale()` while `deAuthoriseSale()` is mid-execution
 * - This creates a race condition that spans multiple contract functions
 * - The attack exploits the temporal gap between the external call and state cleanup
 * 
 * **Realistic Attack Vector:**
 * - The notification callback appears legitimate (notifying buyers of cancellation)
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The multi-transaction nature makes it harder to detect through simple static analysis
 * - The attack requires pre-positioning (becoming an authorized buyer) making it stateful and strategic
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify authorized buyer about cancellation if one exists
    address authorizedBuyer = authorisedSaleAddresses[x][y];
    if (authorizedBuyer != 0x0) {
        // External call before state update - vulnerable to reentrancy
        bool success = authorizedBuyer.call(bytes4(keccak256("onSaleCancelled(uint256,uint256)")), x, y);
        // Continue execution regardless of callback result
    }
    
    // State updates occur after external call - vulnerable window
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    authorisedSaleAddresses[x][y] = 0x0;
    authorisedSalePrices[x][y] = 0;
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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