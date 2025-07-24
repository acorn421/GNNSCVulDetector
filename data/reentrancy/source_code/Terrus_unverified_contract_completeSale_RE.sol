/*
 * ===== SmartInject Injection Details =====
 * Function      : completeSale
 * Vulnerability : Reentrancy
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
 * **Specific Changes Made:**
 * 
 * 1. **Moved External Call Earlier**: The `seller.transfer(forSeller)` call is now executed BEFORE state updates, violating the checks-effects-interactions pattern.
 * 
 * 2. **State Updates After External Call**: All critical state modifications (plot ownership, clearing authorization mappings) now happen AFTER the external call, creating a window for reentrancy exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Sale Setup:**
 * - Seller calls `authoriseSale(x, y, maliciousContract, price)` to authorize a sale to their malicious contract
 * - This sets `authorisedSaleAddresses[x][y] = maliciousContract` and `authorisedSalePrices[x][y] = price`
 * 
 * **Transaction 2 - Reentrancy Attack:**
 * - Malicious contract calls `completeSale(x, y)` with the correct payment
 * - Function executes checks (all pass since authorization still exists)
 * - `seller.transfer(forSeller)` is called, triggering the malicious contract's fallback function
 * - **Reentrancy occurs**: Malicious contract's fallback function calls `completeSale(x, y)` again
 * - Since state hasn't been updated yet, `authorisedSaleAddresses[x][y]` and `authorisedSalePrices[x][y]` still contain valid values
 * - The reentrant call passes all checks and transfers funds again
 * - This can be repeated multiple times before the original call completes
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The authorization mappings (`authorisedSaleAddresses`, `authorisedSalePrices`) must be set in a prior transaction through `authoriseSale()` - they cannot be manipulated in the same transaction as the attack.
 * 
 * 2. **Authorization Dependency**: The vulnerability depends on pre-existing authorization state that persists between transactions. Without this persistent state, the attack cannot succeed.
 * 
 * 3. **Accumulated State Exploitation**: The attack exploits the fact that state changes are deferred until after the external call, allowing multiple reentrancy calls to see the same "authorized" state before it gets cleared.
 * 
 * 4. **Economic Incentive**: The attack becomes profitable only when the same sale authorization can be used multiple times, requiring the state to persist across multiple reentrant calls within the same transaction context.
 * 
 * This creates a realistic vulnerability where an attacker must first establish authorization (transaction 1) and then exploit the reentrancy in the payment flow (transaction 2), making it a genuine stateful, multi-transaction vulnerability.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Vulnerable: External call before state updates
    seller.transfer(forSeller);
    
    // State updates occur after external call, allowing reentrancy
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    plot.owner = buyer;
    plot.saleCount += 1;
    authorisedSaleAddresses[x][y] = 0x0;
    authorisedSalePrices[x][y] = 0;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    PlotSale(x, y, seller, buyer, price, false);
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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