/*
 * ===== SmartInject Injection Details =====
 * Function      : startInvasion
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by violating the Checks-Effects-Interactions pattern. The vulnerability allows an attacker to exploit the gap between external calls and state updates through multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. **Separated external call**: Moved `zombiemain.seeZombieDna()` to a separate line before state updates, creating a reentrancy window
 * 2. **Preserved external call sequence**: Kept `zombiemain.seeZombieRole()` call in the second loop before the critical `TotalTeamCount` increment
 * 3. **Added vulnerability comments**: Documented the specific attack vectors for clarity
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `startInvasion()` with malicious zombie contract
 * 2. **Reentrant Call**: During `seeZombieDna()` or `seeZombieRole()`, malicious contract calls back to `startInvasion()`
 * 3. **State Exploitation**: Second call operates on partially updated state (some zombies marked as `notAtHome` but `TotalTeamCount` not yet incremented)
 * 4. **Transaction 2**: Attacker completes the exploitation by accessing areas that should be full or using zombies that should be unavailable
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the attacker to first deploy a malicious zombie contract that implements the DNA/role interface
 * - The reentrant call must happen during the external call window, exploiting the inconsistent state
 * - The attack relies on accumulated state changes from the first transaction affecting the second transaction's execution
 * - The exploit cannot be completed in a single atomic transaction because it depends on the specific sequence of external calls and state updates
 * 
 * **Realistic Impact:**
 * - Attacker can bypass area team limits by reentering before `TotalTeamCount` increment
 * - Multiple invasions can be started with the same zombies before they're marked as `notAtHome`
 * - Resource exhaustion attacks against area availability
 * - Team hash collisions and duplicate team creation
 */
pragma solidity ^0.4.18;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}


contract zombieToken {
  function mint(address to, uint256 value) public returns (bool success);
}

contract zombieMain {
  function checkAllOwner(uint256[] _tokenId, address owner) public view returns (bool);
  function seeZombieRole(uint256 _tokenId) public view returns (uint16 roletype);
  function seeZombieColor(uint256 _tokenId) public view returns (uint8 color);
  function seeZombieStar(uint256 _tokenId) public view returns (uint8 star);
  function seeZombieDna(uint256 _tokenId) public view returns (bytes32 dna);
}

contract zombieInvasion is Ownable{
    using SafeMath for uint256;
    
    zombieToken zombietoken = zombieToken(0x2Bb48FE71ba5f73Ab1c2B9775cfe638400110d34);
    zombieMain zombiemain = zombieMain(0x58fd762F76D57C6fC2a480F6d26c1D03175AD64F);

    struct Zombie {
      uint32 readyTime;//剩餘可出戰時間
      bool notAtHome;  //是否離家
      uint16 undeadsTime;//不死次數
    }

    struct Area {
      uint starLimit; 
      uint8 TeamMemberlimitCount; // 5
      uint8[] roletype;     //  4,4,99,99,99
      uint TotallimitTeamCount;
      uint TotalTeamCount;
      string name;
      uint ZOBRevenue;
      bool isOpen;
      uint32 duration;
    }

    struct Team {
      bool isCharge;
      uint areaID;
      uint[] Zombies;
      uint32 awardTime;
      address Owner;
      bytes32 teamHash;
      uint blocknumber;
    }
    
    Area[] public areas;

    mapping (uint=>Zombie) public zombies;
    mapping (bytes32=>Team) public teams;

    event StartInvasion(bytes32 indexed teamhash, uint _areaId,uint[] _zombieId,address player);
    event AwardInvation(bytes32 indexed teamhash, bool InvationResult, uint ZOBRevenue, address player);

    modifier onlyOwnerOf(uint[] _zombieId) {
      require(zombiemain.checkAllOwner(_zombieId, msg.sender));
      _;
    }


  function startInvasion(uint _areaId, uint[] _zombieId) public onlyOwnerOf(_zombieId){
    require(areas[_areaId].TotallimitTeamCount >= areas[_areaId].TotalTeamCount + 1);
    require(areas[_areaId].isOpen);
    require(areas[_areaId].TeamMemberlimitCount >= _zombieId.length);

    bytes32 teamHash = block.blockhash(block.number-1);

    for(uint16 i = 0; i<_zombieId.length; i++){
      //確保殭屍都在家，並且可以出戰
      require(now > zombies[_zombieId[i]].readyTime);
      require(!zombies[_zombieId[i]].notAtHome);

      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // VULNERABILITY: External call to potentially malicious contract before state updates
      // This allows attacker to reenter during DNA validation
      bytes32 zombieDna = zombiemain.seeZombieDna(_zombieId[i]);
      
      teamHash = keccak256(teamHash,now,_areaId,zombieDna);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

      zombies[_zombieId[i]].notAtHome = true;
      zombies[_zombieId[i]].readyTime = uint32(now + areas[_areaId].duration);
    }

    //職業都必須符合條件
    for(uint16 a = 0; a<areas[_areaId].roletype.length; a++){
      if(areas[_areaId].roletype[a] == 99) continue;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // VULNERABILITY: Another external call before team count increment
      // Allows reentrancy to exploit partially updated zombie states
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      if(zombiemain.seeZombieRole(_zombieId[a]) != areas[_areaId].roletype[a]) revert();
    }    

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // VULNERABILITY: State update occurs after external calls, creating race condition
    // Attacker can reenter multiple times before this increment happens
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    areas[_areaId].TotalTeamCount ++;

    require(teams[teamHash].areaID == 0);
    teams[teamHash] = Team(false,_areaId,_zombieId,uint32(now+areas[_areaId].duration),msg.sender,teamHash,block.number + 1);
    
    StartInvasion(teamHash, _areaId, _zombieId, msg.sender);
  }

  function awardInvasion(bytes32 _teamId) public {
    require(teams[_teamId].Owner == msg.sender);
    require(now >= teams[_teamId].awardTime);
    require(!teams[_teamId].isCharge);
    uint totalUndeadsTime;
    uint totalStar;
    uint dieNumber;
    uint16 i;
    uint16 ii;

    uint[] memory zb =  teams[_teamId].Zombies;

    for(i=0;i<zb.length;i++){
        totalUndeadsTime += zombies[zb[i]].undeadsTime;
        totalStar += zombiemain.seeZombieStar(zb[i]);
    }

    if(totalStar<areas[teams[_teamId].areaID].starLimit){
        dieNumber = totalStar*9500/(areas[teams[_teamId].areaID].starLimit)+totalUndeadsTime*10;
    }else{
        dieNumber = totalStar*100/(areas[teams[_teamId].areaID].starLimit)+9400+totalUndeadsTime;
    }

    if(dieNumber <= uint(keccak256(teams[_teamId].teamHash, now, block.blockhash(block.number-1),block.blockhash(teams[_teamId].blocknumber))) % 10000) {
      //Lose
      for(ii = 0; ii<zb.length; ii++){
        zombies[zb[ii]].readyTime = uint32(now + 7 days);
        zombies[zb[ii]].undeadsTime = 0;
        zombies[zb[ii]].notAtHome = false;
      }
      AwardInvation(_teamId, false, 0, msg.sender);
    } else {
      //Win
      for(ii = 0; ii<zb.length; ii++){
        zombies[zb[ii]].undeadsTime ++;
        zombies[zb[ii]].notAtHome = false;
      }
      zombietoken.mint(teams[_teamId].Owner, areas[teams[_teamId].areaID].ZOBRevenue);
      AwardInvation(_teamId, true, areas[teams[_teamId].areaID].ZOBRevenue, msg.sender);
    }

    teams[_teamId].isCharge = true;
    areas[teams[_teamId].areaID].TotalTeamCount --;
  }

  function addArea(uint starLimit,uint8 TeamMemberlimitCount,uint8[] roletype,uint _totallimitTeamCount,string name,uint ZOBRevenue,bool isOpen,uint32 duration) public onlyOwner{
      areas.push(Area(starLimit, TeamMemberlimitCount, roletype, _totallimitTeamCount, 0, name, ZOBRevenue, isOpen, duration));
  }
  
  function closeArea(uint areaId) public onlyOwner{
      areas[areaId].isOpen = false;
  }

}
