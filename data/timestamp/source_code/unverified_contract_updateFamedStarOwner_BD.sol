/*
 * ===== SmartInject Injection Details =====
 * Function      : updateFamedStarOwner
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
 * Introduced a timestamp-based cooldown mechanism for star ownership transfers that creates a multi-transaction vulnerability. The vulnerability uses block.timestamp for time-based access control and stores timing information in state variables, allowing miners to manipulate timestamps between transactions.
 * 
 * SPECIFIC CHANGES MADE:
 * 1. Added timestamp-based cooldown logic requiring 24-hour waiting period between transfers
 * 2. Used block.timestamp for time calculations without proper validation
 * 3. Stored timing data in state variables using assembly and keccak256 hashing
 * 4. Created a two-transaction requirement for ownership transfers
 * 
 * HOW THE VULNERABILITY CAN BE EXPLOITED:
 * Transaction 1: Call updateFamedStarOwner to initialize the cooldown timestamp
 * Transaction 2: Miners can manipulate block.timestamp to be >= lastTransferTime + 86400 to bypass the cooldown
 * 
 * MULTI-TRANSACTION EXPLOITATION REQUIREMENTS:
 * - First transaction initializes the cooldown timestamp and exits early
 * - Second transaction attempts to complete the ownership transfer
 * - Miners can manipulate block.timestamp between transactions to bypass the 24-hour cooldown
 * - The stored state from the first transaction enables the timestamp manipulation in the second transaction
 * 
 * The vulnerability is stateful because it relies on the timestamp stored in the first transaction, and requires multiple transactions because the initial call just sets up the cooldown state while the subsequent call performs the actual transfer check.
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

      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      // Add timestamp-based cooldown mechanism for ownership transfers
      uint currentTimestamp = block.timestamp;
      
      // If star has an owner, enforce 24-hour cooldown period
      if (star.owner != address(0x0)) {
          // Store the last transfer timestamp using a predictable pattern
          bytes32 slot = keccak256(id, "lastTransfer");
          uint lastTransferTime;
          assembly {
              lastTransferTime := sload(slot)
          }
          // If this is the first check, initialize the timestamp
          if (lastTransferTime == 0) {
              // Store current timestamp in a way that can be manipulated
              assembly {
                  sstore(slot, currentTimestamp)
              }
              return; // Require second transaction to complete transfer
          }
          // Check if cooldown period has passed (24 hours = 86400 seconds)
          require(currentTimestamp >= lastTransferTime + 86400, "Transfer cooldown active");
      }

      stars[id].owner = newOwner;
      
      // Update the last transfer timestamp for future cooldown checks
      bytes32 slotUpdate = keccak256(id, "lastTransfer");
      assembly {
          sstore(slotUpdate, currentTimestamp)
      }
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
