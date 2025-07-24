/*
 * ===== SmartInject Injection Details =====
 * Function      : awardInvation
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based bonus accumulation and reward manipulation system:
 * 
 * 1. **Added State Variable**: `teams[_teamId].lastAwardAttempt` tracks the timestamp of the last award attempt, creating persistent state between transactions.
 * 
 * 2. **Time-Based Bonus Accumulation**: 
 *    - Calculates `timeDiff` between current timestamp and last attempt
 *    - Provides increasing bonus points (100 per 5-minute interval) that reduce the `dieNumber`
 *    - Lower `dieNumber` increases win probability significantly
 * 
 * 3. **Reward Multiplier System**:
 *    - Implements time-based reward multipliers (2x for 30+ minutes, 1x for 15+ minutes)
 *    - Multiplies the final token reward based on time elapsed
 * 
 * 4. **Multi-Transaction Exploitation**:
 *    - **First Transaction**: Calls `awardInvation` to set `lastAwardAttempt` timestamp
 *    - **Wait Period**: Attacker waits for beneficial time intervals (5+ minutes for bonus, 30+ minutes for max reward)
 *    - **Second Transaction**: Calls `awardInvation` again to exploit accumulated time bonuses
 * 
 * 5. **Realistic Vulnerability Pattern**:
 *    - Appears as a legitimate "cooldown bonus" or "patience reward" mechanism
 *    - Uses `block.timestamp` (now) for critical game logic calculations
 *    - Creates predictable manipulation opportunities based on mining control
 * 
 * **Exploitation Scenario**:
 * - Attacker calls function once to initialize timestamp
 * - Waits exactly 30 minutes (or controls block timestamps)
 * - Calls function again to receive 2000 point bonus (reducing die number) and 2x reward multiplier
 * - Can repeat pattern to consistently win with higher rewards
 * 
 * This creates a realistic timestamp dependence where success depends on timing across multiple transactions rather than single-transaction exploits.
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
  constructor() public {
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
    emit OwnershipTransferred(owner, newOwner);
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
      uint lastAwardAttempt;
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

      teamHash = keccak256(abi.encodePacked(teamHash,now,_areaId,zombiemain.seeZombieDna(_zombieId[i])));

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
    teams[teamHash] = Team(false,_areaId,_zombieId,uint32(now+areas[_areaId].duration),msg.sender,teamHash,block.number + 1, 0);
    
    emit StartInvasion(teamHash, _areaId, _zombieId, msg.sender);
  }

  function awardInvation(bytes32 _teamId) public {
    require(teams[_teamId].Owner == msg.sender);
    require(now >= teams[_teamId].awardTime);
    require(!teams[_teamId].isCharge);
    uint totalUndeadsTime = 0;
    uint totalStar = 0;
    uint dieNumber = 0;

    uint[] memory zb =  teams[_teamId].Zombies;

    for(uint i=0;i<zb.length;i++){
        totalUndeadsTime += zombies[zb[i]].undeadsTime;
        totalStar += zombiemain.seeZombieStar(zb[i]);
    }

    if(totalStar<areas[teams[_teamId].areaID].starLimit){
        dieNumber = totalStar*9500/(areas[teams[_teamId].areaID].starLimit)+totalUndeadsTime*10;
    }else{
        dieNumber = totalStar*100/(areas[teams[_teamId].areaID].starLimit)+9400+totalUndeadsTime;
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Store block timestamp for time-based calculations
    if(teams[_teamId].lastAwardAttempt == 0) {
        teams[_teamId].lastAwardAttempt = now;
    }
    
    // Calculate time-based bonus multiplier that accumulates over multiple attempts
    uint timeDiff = now - teams[_teamId].lastAwardAttempt;
    uint timeBonus = 0;
    if(timeDiff >= 300) { // 5 minutes
        timeBonus = (timeDiff / 300) * 100; // 100 points per 5-minute interval
        if(timeBonus > 2000) timeBonus = 2000; // Cap at 2000 points
    }
    
    // Apply time-based manipulation to die number calculation
    if(timeBonus > 0) {
        dieNumber = dieNumber > timeBonus ? dieNumber - timeBonus : 0;
    }
    
    // Update last attempt timestamp for next calculation
    teams[_teamId].lastAwardAttempt = now;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if(dieNumber <= uint(keccak256(abi.encodePacked(teams[_teamId].teamHash, now, block.blockhash(block.number-1),block.blockhash(teams[_teamId].blocknumber)))) % 10000) {
      //Lose
      for(uint16 ii = 0; ii<zb.length; ii++){
        zombies[zb[ii]].readyTime = uint32(now + 7 days);
        zombies[zb[ii]].undeadsTime = 0;
        zombies[zb[ii]].notAtHome = false;
      }
      emit AwardInvation(_teamId, false, 0, msg.sender);
    } else {
      //Win
      for(uint16 jj = 0; jj<zb.length; jj++){
        zombies[zb[jj]].undeadsTime ++;
        zombies[zb[jj]].notAtHome = false;
      }
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Calculate time-based reward multiplier
      uint rewardMultiplier = 1;
      if(timeDiff >= 1800) { // 30 minutes
        rewardMultiplier = 2;
      } else if(timeDiff >= 900) { // 15 minutes  
        rewardMultiplier = 1;
      }
      
      uint finalReward = areas[teams[_teamId].areaID].ZOBRevenue * rewardMultiplier;
      zombietoken.mint(teams[_teamId].Owner, finalReward);
      emit AwardInvation(_teamId, true, finalReward, msg.sender);
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
