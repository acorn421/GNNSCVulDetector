/*
 * ===== SmartInject Injection Details =====
 * Function      : bornFamedStar
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Manipulation Before External Call**: Added a temporary marker (stars[starID].lc = 999999) before the external call to simulate processing state, but this creates a window for reentrancy exploitation.
 * 
 * 2. **External Call with State Reset**: The external call is made with the temporary marker value, then the state is reset to the original value. This creates a critical window where the state is inconsistent.
 * 
 * 3. **Multi-Transaction Exploitation Vector**: 
 *    - **Transaction 1**: Attacker calls bornFamedStar through a malicious nova contract
 *    - **During External Call**: The malicious labContract can re-enter bornFamedStar before the state is properly updated
 *    - **Transaction 2**: During reentrancy, the star.lc value is read as the original value (not the marker), allowing the attacker to bypass the processing logic
 *    - **State Accumulation**: Multiple reentrant calls can increment the lc counter multiple times or claim ownership multiple times before the original call completes
 * 
 * 4. **Persistence Between Transactions**: The vulnerability exploits the fact that state changes persist between the reentrant calls, allowing an attacker to manipulate the accumulated state across multiple function invocations.
 * 
 * 5. **Realistic Implementation**: The vulnerability mimics real-world patterns where developers try to implement processing flags but fail to properly handle reentrancy, creating a subtle but exploitable security flaw.
 * 
 * The vulnerability requires multiple transactions because:
 * - The first transaction initiates the process and sets the temporary state
 * - The reentrant calls exploit the inconsistent state before the original transaction completes
 * - The accumulated effect of multiple reentrant calls creates the actual exploitation vector
 * - Single transaction exploitation is prevented by the external call requirement and state persistence logic
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

      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Mark star as being processed to prevent double-claiming
      stars[starID].lc = 999999; // Temporary marker for processing
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      bool isGot;
      var labContract = NovaLabInterface(labAddress);
      isGot = labContract.bornFamedStar(star.lc);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Reset processing marker and apply actual logic
      stars[starID].lc = star.lc;
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      if (isGot) {
          stars[starID].owner = userAddress;
          return (starID, stars[starID].name);
      } else {
          stars[starID].lc++;
          return (0, 0);
      }
  }
}