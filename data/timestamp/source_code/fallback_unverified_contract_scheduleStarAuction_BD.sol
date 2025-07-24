/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleStarAuction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction auction system. The vulnerability requires: 1) Manager schedules auction using block.timestamp, 2) Users place bids during auction period checking block.timestamp, 3) Auction finalization depends on block.timestamp comparison. Miners can manipulate block.timestamp to extend/shorten auction periods, affect bid timing, or manipulate auction finalization, potentially allowing them to win auctions unfairly or prevent legitimate bidders from participating.
 */
pragma solidity ^0.4.17;

contract NovaLabInterface {
    function bornFamedStar(uint lc) external constant returns(bool) {}
}

contract NovaAccessControl {
  mapping (address => bool) managers;
  address cfoAddress;

  function NovaAccessControl() public {
    managers[msg.sender] = true;
  }

  modifier onlyManager() {
    require(managers[msg.sender]);
    _;
  }

  function setManager(address _newManager) external onlyManager {
    require(_newManager != address(0));
    managers[_newManager] = true;
  }

  function removeManager(address mangerAddress) external onlyManager {
    require(mangerAddress != msg.sender);
    managers[mangerAddress] = false;
  }

  function updateCfo(address newCfoAddress) external onlyManager {
    require(newCfoAddress != address(0));
    cfoAddress = newCfoAddress;
  }
}

contract FamedStar is NovaAccessControl {
  struct Star {
    bytes32 name;
    uint mass;
    uint lc;
    address owner;
  }

  struct StarAuction {
    uint starId;
    uint startTime;
    uint endTime;
    uint minBid;
    address highestBidder;
    uint highestBid;
    bool active;
  }

  mapping (uint => StarAuction) public starAuctions;
  mapping (uint => bool) public auctionExists;

  function scheduleStarAuction(uint starId, uint duration, uint minBid) external onlyManager {
    require(starId > 0 && starId < stars.length);
    require(duration > 0);
    require(minBid > 0);
    require(!auctionExists[starId]);
    var star = stars[starId];
    require(star.mass > 0);
    // Vulnerable: Using block.timestamp for time-dependent logic
    uint startTime = block.timestamp;
    uint endTime = startTime + duration;
    starAuctions[starId] = StarAuction({
      starId: starId,
      startTime: startTime,
      endTime: endTime,
      minBid: minBid,
      highestBidder: address(0),
      highestBid: 0,
      active: true
    });
    auctionExists[starId] = true;
  }

  function placeBid(uint starId) external payable {
    require(auctionExists[starId]);
    StarAuction storage auction = starAuctions[starId];
    require(auction.active);
    // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
    require(block.timestamp >= auction.startTime);
    require(block.timestamp <= auction.endTime);
    require(msg.value > auction.minBid);
    require(msg.value > auction.highestBid);
    // Refund previous highest bidder
    if (auction.highestBidder != address(0)) {
      auction.highestBidder.transfer(auction.highestBid);
    }
    auction.highestBidder = msg.sender;
    auction.highestBid = msg.value;
  }

  function finalizeAuction(uint starId) external {
    require(auctionExists[starId]);
    StarAuction storage auction = starAuctions[starId];
    require(auction.active);
    // Vulnerable: Timestamp dependence - miners can manipulate when auction ends
    require(block.timestamp > auction.endTime);
    if (auction.highestBidder != address(0)) {
      // Transfer star ownership to highest bidder
      stars[starId].owner = auction.highestBidder;
      // Transfer funds to CFO
      if (cfoAddress != address(0)) {
        cfoAddress.transfer(auction.highestBid);
      }
    }
    auction.active = false;
  }

  address public labAddress;
  address public novaAddress;
  Star[] stars;
  mapping (bytes32 => uint) public famedStarNameToIds;
  mapping (uint => uint) public famedStarMassToIds;

  function FamedStar() public {
      // add placeholder
      _addFamedStar("placeholder", 0, 0);
  }

  function _bytes32ToString(bytes32 x) internal pure returns (string) {
    bytes memory bytesString = new bytes(32);
    uint charCount = 0;
    for (uint j = 0; j < 32; j++) {
        byte char = byte(uint8(uint(x) / (2**(8*(31 - j)))));
        if (char != 0) {
            bytesString[charCount] = char;
            charCount++;
        }
    }
    bytes memory bytesStringTrimmed = new bytes(charCount);
    for (j = 0; j < charCount; j++) {
        bytesStringTrimmed[j] = bytesString[j];
    }
    return string(bytesStringTrimmed);
  }

  function _stringToBytes32(string source) internal pure returns (bytes32 result) {
    bytes memory tempEmptyStringTest = bytes(source);
    if (tempEmptyStringTest.length == 0) {
        return 0x0;
    }
    assembly {
        result := mload(add(source, 32))
    }
  }

  function updateLabAddress(address addr) external onlyManager {
      labAddress = addr;
  }

  function updateNovaAddress(address addr) external onlyManager {
      novaAddress = addr;
  }

  function addFamedStar(string name, uint mass, uint lc) external onlyManager {
      _addFamedStar(name, mass, lc);
  }

  function _addFamedStar(string name, uint mass, uint lc) internal {
      require(bytes(name).length <= 32);
      var bN = _stringToBytes32(name);
      // no repeat on name
      require(famedStarNameToIds[bN] == 0);
      // no repeat on mass
      require(famedStarMassToIds[mass] == 0);
      var id = stars.push(Star({
          name: bN,
          mass: mass,
          lc: lc,
          owner: 0x0
      })) - 1;
      famedStarNameToIds[bN] = id;
      famedStarMassToIds[mass] = id;
  }

  function getFamedStarByID(uint id) public constant returns(uint starID, string name, uint mass, address owner) {
      require(id > 0 && id < stars.length);
      var star = stars[id];
      return (id, _bytes32ToString(star.name), star.mass, star.owner);
  }

  function getFamedStarByName(string n) public constant returns(uint starID, string name, uint mass, address owner) {
      starID = famedStarNameToIds[_stringToBytes32(n)];
      require(starID > 0);
      var star = stars[starID];
      return (starID, n, star.mass, star.owner);
  }

  function getFamedStarByMass(uint m) public constant returns(uint starID, string name, uint mass, address owner) {
      starID = famedStarMassToIds[m];
      require(starID > 0);
      var star = stars[starID];
      return (starID, _bytes32ToString(star.name), star.mass, star.owner);
  }

  function updateFamedStarOwner(uint id, address newOwner) external {
      require(msg.sender == novaAddress);
      require(id > 0 && id < stars.length);
      var star = stars[id];
      require(star.mass > 0);
      stars[id].owner = newOwner;
  }

  function bornFamedStar(address userAddress, uint mass) external returns(uint id, bytes32 name) {
      require(msg.sender == novaAddress);
      var starID = famedStarMassToIds[mass];
      if (starID == 0) {
          return (0, 0);
      }
      var star = stars[starID];
      if (star.owner != address(0x0)) {
          return (0, 0);
      }
      bool isGot;
      var labContract = NovaLabInterface(labAddress);
      isGot = labContract.bornFamedStar(star.lc);
      if (isGot) {
          stars[starID].owner = userAddress;
          return (starID, stars[starID].name);
      } else {
          stars[starID].lc++;
          return (0, 0);
      }
  }
}
