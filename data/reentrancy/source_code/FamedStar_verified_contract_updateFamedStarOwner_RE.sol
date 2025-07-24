/*
 * ===== SmartInject Injection Details =====
 * Function      : updateFamedStarOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner.call()` before the state update
 * 2. The call notifies the new owner about the ownership transfer with the star ID and previous owner
 * 3. The state update (`stars[id].owner = newOwner`) happens after the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract and calls `updateFamedStarOwner` with their contract as `newOwner`
 * 2. **During Transaction 1**: The external call triggers the attacker's `onOwnershipTransfer` callback
 * 3. **Transaction 2 (via callback)**: The malicious contract can call `updateFamedStarOwner` again or other functions that depend on the star's current ownership state
 * 4. **State Inconsistency**: Since the original transaction hasn't completed the state update yet, the attacker can exploit the inconsistent state where the external call has been made but `stars[id].owner` hasn't been updated
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first set up a malicious contract that implements the callback
 * - The exploitation happens through the callback mechanism, which creates a new transaction context
 * - The attacker needs to accumulate state changes across multiple calls to fully exploit the vulnerability
 * - The timing between the external call and state update creates a window that can only be exploited through sequential transactions
 * 
 * **Exploitation Impact:**
 * - The attacker can manipulate ownership states during the callback
 * - They can potentially transfer ownership to multiple parties simultaneously
 * - The inconsistent state between transactions allows for double-spending-like attacks on star ownership
 * - The vulnerability persists across multiple function calls, making it a stateful vulnerability
 * 
 * This vulnerability is realistic because ownership notification is a common pattern in NFT and asset management contracts, making the external call a natural business logic addition.
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

      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Notify the new owner about the ownership transfer
      if (newOwner != address(0)) {
          // Vulnerability: External call before state update allows reentrancy
          newOwner.call(bytes4(keccak256("onOwnershipTransfer(uint256,address)")), id, star.owner);
      }

      // State update happens after external call - classic reentrancy vulnerability
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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