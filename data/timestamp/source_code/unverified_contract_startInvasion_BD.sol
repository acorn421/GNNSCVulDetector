/*
 * ===== SmartInject Injection Details =====
 * Function      : startInvasion
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability where players can exploit time-based bonuses to gain unfair advantages. The vulnerability creates time windows (daily 8-16 hour periods and weekends) where invasion cooldowns are reduced by 20% and reward collection is 10% faster. This requires multiple transactions: first to discover the timing pattern, then to repeatedly exploit it during bonus windows. The vulnerability is stateful because it depends on accumulated timing knowledge and requires sequential invasions to maximize benefit. Players who understand the timestamp-based bonus system can plan multiple invasions during favorable time windows, creating a significant advantage over those who don't exploit the timing dependency.
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based bonus that accumulates across multiple invasions
    uint32 timeBonus = 0;
    uint32 hoursSinceEpoch = uint32(now / 1 hours);
    
    // Players get accumulated bonuses during certain time windows
    if (hoursSinceEpoch % 24 >= 8 && hoursSinceEpoch % 24 <= 16) {
        timeBonus = 1 hours; // 8 hour bonus window daily
    }
    
    // Weekend bonus (simplified - every 7 days starting from timestamp 0)
    if ((hoursSinceEpoch / 24) % 7 >= 5) {
        timeBonus += 2 hours; // Weekend bonus stacks
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    for(uint16 i = 0; i<_zombieId.length; i++){
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      //確保殭屍都在家，並且可以出戰  
      // Vulnerable: reduced cooldown based on timestamp allows faster consecutive invasions
      require(now > zombies[_zombieId[i]].readyTime - timeBonus);
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      require(!zombies[_zombieId[i]].notAtHome);

      teamHash = keccak256(teamHash,now,_areaId,zombiemain.seeZombieDna(_zombieId[i]));

      zombies[_zombieId[i]].notAtHome = true;
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Store timestamp in state for later exploitation
      uint32 invasionTime = uint32(now);
      
      // Vulnerable: shorter cooldown during bonus periods creates unfair advantage
      uint32 cooldownDuration = areas[_areaId].duration;
      if (timeBonus > 0) {
          cooldownDuration = cooldownDuration * 80 / 100; // 20% reduction during bonus time
      }
      
      zombies[_zombieId[i]].readyTime = invasionTime + cooldownDuration;
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    //職業都必須符合條件
    for(uint16 a = 0; a<areas[_areaId].roletype.length; a++){
      if(areas[_areaId].roletype[a] == 99) continue;
      if(zombiemain.seeZombieRole(_zombieId[a]) != areas[_areaId].roletype[a]) revert();
    }    

    areas[_areaId].TotalTeamCount ++;

    require(teams[teamHash].areaID == 0);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Vulnerable: award time also benefits from timestamp manipulation
    uint32 awardTime = uint32(now + areas[_areaId].duration);
    if (timeBonus > 0) {
        awardTime = uint32(now + (areas[_areaId].duration * 90 / 100)); // 10% faster rewards
    }
    
    teams[teamHash] = Team(false,_areaId,_zombieId,awardTime,msg.sender,teamHash,block.number + 1);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    
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
      for(i = 0; i<zb.length; i++){
        zombies[zb[i]].readyTime = uint32(now + 7 days);
        zombies[zb[i]].undeadsTime = 0;
        zombies[zb[i]].notAtHome = false;
      }
      AwardInvation(_teamId, false, 0, msg.sender);
    } else {
      //Win
      for(i = 0; i<zb.length; i++){
        zombies[zb[i]].undeadsTime ++;
        zombies[zb[i]].notAtHome = false;
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
