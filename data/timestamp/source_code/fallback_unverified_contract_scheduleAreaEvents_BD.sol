/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleAreaEvents
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 11 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where scheduled area events rely on 'now' (block.timestamp) for timing validation. The vulnerability is stateful and multi-transaction: 1) Owner must first call scheduleAreaEvents() to set up the event timing, 2) Then any user can call triggerScheduledEvent() once the timestamp condition is met, 3) This permanently modifies the area's ZOBRevenue state. Malicious miners can manipulate block timestamps within consensus rules to trigger events prematurely or delay them, affecting the game's economy and fairness.
 */
pragma solidity ^0.4.18;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

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

contract zombieInvasion is Ownable {
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to track scheduled events
    mapping (uint => uint32) public areaEventSchedule;
    mapping (uint => bool) public areaEventTriggered;
    
    function scheduleAreaEvents(uint _areaId, uint32 _eventDelay) public onlyOwner {
        require(_areaId < areas.length);
        require(_eventDelay > 0);
        areaEventSchedule[_areaId] = uint32(now + _eventDelay);
        areaEventTriggered[_areaId] = false;
    }
    
    function triggerScheduledEvent(uint _areaId) public {
        require(_areaId < areas.length);
        require(areaEventSchedule[_areaId] > 0);
        require(!areaEventTriggered[_areaId]);
        require(now >= areaEventSchedule[_areaId]);
        areas[_areaId].ZOBRevenue = areas[_areaId].ZOBRevenue.mul(15).div(10); // 1.5x multiplier
        areaEventTriggered[_areaId] = true;
    }
    
    function resetAreaEvent(uint _areaId) public onlyOwner {
        require(_areaId < areas.length);
        areaEventSchedule[_areaId] = 0;
        areaEventTriggered[_areaId] = false;
    }
    // === END FALLBACK INJECTION ===

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
      require(now > zombies[_zombieId[i]].readyTime);
      require(!zombies[_zombieId[i]].notAtHome);

      teamHash = keccak256(teamHash,now,_areaId,zombiemain.seeZombieDna(_zombieId[i]));

      zombies[_zombieId[i]].notAtHome = true;
      zombies[_zombieId[i]].readyTime = uint32(now + areas[_areaId].duration);
    }

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
