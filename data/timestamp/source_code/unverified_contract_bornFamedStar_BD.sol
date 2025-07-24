/*
 * ===== SmartInject Injection Details =====
 * Function      : bornFamedStar
 * Vulnerability : Timestamp Dependence
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
 * This vulnerability introduces timestamp dependence through two mechanisms:
 * 
 * 1. **Time-based Availability Windows**: Stars can only be born during specific time periods (last 30 minutes of each hour). This creates predictable time windows that can be exploited by miners or attackers who can manipulate block timestamps within the allowed 900-second range.
 * 
 * 2. **Timestamp-based State Corruption**: When star birthing fails, the function stores `block.timestamp` in the `star.lc` field instead of incrementing it. This corrupts the intended logic counter with timestamp values, creating unpredictable behavior in subsequent calls to the external lab contract.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Attacker calls during an unavailable time window, causing the function to return early without consuming gas for the external call
 * - **Transaction 2**: Attacker waits for or manipulates timestamp to hit the available window, then calls again when `timeWindow >= 1800`
 * - **Transaction 3+**: If the lab contract call fails, the `star.lc` field gets corrupted with a timestamp value, affecting future calls to `labContract.bornFamedStar(star.lc)` in unpredictable ways
 * 
 * **Stateful Requirements:**
 * - The vulnerability requires multiple transactions because the time window check creates different behavior at different timestamps
 * - Failed attempts corrupt the star's state (lc field) with timestamp values, affecting subsequent transactions
 * - The exploitation requires timing across multiple blocks/transactions to hit the vulnerable time windows
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
        byte char = byte(bytes32(uint(x) * 2 ** (8 * j)));
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

      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      // Time-based availability window: stars can only be born during specific time periods
      // Uses block.timestamp % 3600 to create hourly windows where stars are available
      uint timeWindow = block.timestamp % 3600; // 1-hour cycles
      if (timeWindow < 1800) { // Only available during first 30 minutes of each hour
          return (0, 0);
      }

      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      bool isGot;
      var labContract = NovaLabInterface(labAddress);
      isGot = labContract.bornFamedStar(star.lc);
      if (isGot) {
          stars[starID].owner = userAddress;
          return (starID, stars[starID].name);
      } else {
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          // Store timestamp of failed attempt for time-based rate limiting
          // This creates persistent state that affects future calls
          stars[starID].lc = block.timestamp; // Overwrite lc with timestamp
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          return (0, 0);
      }
  }
}