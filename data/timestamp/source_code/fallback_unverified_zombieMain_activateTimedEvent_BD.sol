/*
 * ===== SmartInject Injection Details =====
 * Function      : activateTimedEvent
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 12 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This creates a timestamp dependence vulnerability where the contract relies on 'now' (block.timestamp) for critical timing logic. The vulnerability is stateful and multi-transaction: 1) Owner must first call activateTimedEvent() to set eventStartTime, 2) Owner can manipulate event duration by calling extendTimedEvent() in the last hour, 3) Players can claim rewards based on timestamp checks. Malicious miners can manipulate timestamps to extend events or allow/deny reward claims, and the vulnerability persists across multiple transactions through the eventStartTime state variable.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public eventStartTime;
    uint256 public eventDuration = 24 hours;
    uint256 public eventRewardMultiplier = 2;
    bool public timedEventActive = false;
    
    function activateTimedEvent() public onlyOwner {
        require(!timedEventActive);
        eventStartTime = now;
        timedEventActive = true;
    }
    
    function extendTimedEvent(uint256 _additionalTime) public onlyOwner {
        require(timedEventActive);
        require(now >= eventStartTime + eventDuration - 1 hours); // Only extend in last hour
        eventDuration = eventDuration.add(_additionalTime);
    }
    
    function claimTimedEventReward(bytes32 _teamId) public {
        require(timedEventActive);
        require(teams[_teamId].Owner == msg.sender);
        require(teams[_teamId].isCharge);
        require(now >= eventStartTime && now <= eventStartTime + eventDuration);
        
        // Reset team charge status to allow claiming timed event reward
        teams[_teamId].isCharge = false;
        
        uint256 baseReward = areas[teams[_teamId].areaID].ZOBRevenue;
        uint256 timedReward = baseReward.mul(eventRewardMultiplier);
        
        zombietoken.mint(msg.sender, timedReward);
    }
    // === END FALLBACK INJECTION ===

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

      teamHash = keccak256(teamHash,now,_areaId,zombiemain.seeZombieDna(_zombieId[i]));

      zombies[_zombieId[i]].notAtHome = true;
      zombies[_zombieId[i]].readyTime = uint32(now + areas[_areaId].duration);
    }

    //職業都必須符合條件
    for(uint16 a = 0; a<areas[_areaId].roletype.length; a++){
      if(areas[_areaId].roletype[a] == 99) continue;
      if(zombiemain.seeZombieRole(_zombieId[a]) != areas[_areaId].roletype[a]) revert();
    }    

    areas[_areaId].TotalTeamCount ++;

    require(teams[teamHash].areaID == 0);
    teams[teamHash] = Team(false,_areaId,_zombieId,uint32(now+areas[_areaId].duration),msg.sender,teamHash,block.number + 1);
    
    StartInvasion(teamHash, _areaId, _zombieId, msg.sender);
  }

  function awardInvation(bytes32 _teamId) public {
    require(teams[_teamId].Owner == msg.sender);
    require(now >= teams[_teamId].awardTime);
    require(!teams[_teamId].isCharge);
    uint totalUndeadsTime;
    uint totalStar;
    uint dieNumber;

    uint[] memory zb =  teams[_teamId].Zombies;

    uint16 i;
    uint16 ii;
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
