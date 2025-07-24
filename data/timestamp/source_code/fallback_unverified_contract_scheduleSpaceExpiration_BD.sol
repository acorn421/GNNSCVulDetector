/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleSpaceExpiration
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on block.timestamp for critical space expiration logic. The vulnerability is stateful and requires multiple transactions: 1) scheduleSpaceExpiration() sets an expiration time, 2) checkSpaceExpiration() must be called to mark a space as expired, 3) claimExpiredSpace() can then be used to transfer ownership. Miners can manipulate timestamps within acceptable bounds to either prevent expiration or force premature expiration, allowing them to gain unfair advantages in space ownership transfers. The vulnerability persists across transactions through the spaceExpirationTime and spaceExpired mappings.
 */
pragma solidity ^0.4.15;

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
  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

/**
 * @title Stoppable
 * @dev Base contract which allows children to implement a permanent stop mechanism.
 */
contract Stoppable is Ownable {
  event Stop();  

  bool public stopped = false;

  /**
   * @dev Modifier to make a function callable only when the contract is not stopped.
   */
  modifier whenNotStopped() {
    require(!stopped);
    _;
  }

  /**
   * @dev Modifier to make a function callable only when the contract is stopped.
   */
  modifier whenStopped() {
    require(stopped);
    _;
  }

  /**
   * @dev called by the owner to pause, triggers stopped state
   */
  function stop() onlyOwner whenNotStopped public {
    stopped = true;
    Stop();
  }
}

contract SpaceRegistry is Stoppable {
    
    event Add();
    uint constant START_INDEX = 1;
    Space[] spaces;
    mapping(uint => uint) spaceMap;
    mapping(uint => uint[]) userSpaceLookup;
    
    struct Space {
        uint id;
        uint userId;
        bytes userHash;
        uint bottomLeft;
        uint topLeft;
        uint topRight;
        uint bottomRight;
        string txType;
        string txId;
        uint txTime;
        uint created;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // New state variables for the added functions
    mapping(uint => uint) public spaceExpirationTime;
    mapping(uint => bool) public spaceExpired;

    function scheduleSpaceExpiration(uint spaceId, uint expirationDuration) 
        onlyOwner whenNotStopped public {
        require(spaceId > 0);
        require(exists(spaceId));
        require(expirationDuration > 0);
        
        // Set expiration time based on current block timestamp
        spaceExpirationTime[spaceId] = block.timestamp + expirationDuration;
    }
    
    function checkSpaceExpiration(uint spaceId) public returns(bool) {
        require(spaceId > 0);
        require(exists(spaceId));
        
        // Check if space has expired based on block timestamp
        if (block.timestamp >= spaceExpirationTime[spaceId] && 
            spaceExpirationTime[spaceId] > 0) {
            spaceExpired[spaceId] = true;
            return true;
        }
        return false;
    }
    
    function claimExpiredSpace(uint spaceId, uint newUserId) 
        onlyOwner whenNotStopped public {
        require(spaceId > 0);
        require(exists(spaceId));
        require(newUserId > 0);
        // Must first check expiration in a separate transaction
        require(spaceExpired[spaceId] == true);

        // Update the space ownership
        var index = spaceMap[spaceId];
        var space = spaces[index];
        
        // Remove from old user's lookup
        uint oldUserId = space.userId;
        uint[] storage oldUserSpaces = userSpaceLookup[oldUserId];
        for (uint i = 0; i < oldUserSpaces.length; i++) {
            if (oldUserSpaces[i] == spaceId) {
                oldUserSpaces[i] = oldUserSpaces[oldUserSpaces.length - 1];
                oldUserSpaces.length--;
                break;
            }
        }
        
        // Update space with new user
        spaces[index].userId = newUserId;
        userSpaceLookup[newUserId].push(spaceId);
        
        // Reset expiration state
        spaceExpirationTime[spaceId] = 0;
        spaceExpired[spaceId] = false;
    }
    // === END FALLBACK INJECTION ===

    function SpaceRegistry() public {
        spaces.length = START_INDEX;
    }

    function addSpace(
        uint id, uint userId, bytes userHash, uint bottomLeft, uint topLeft, 
        uint topRight, uint bottomRight, string txType, string txId, uint txTime) 
        onlyOwner whenNotStopped public {

        require(id > 0);
        require(spaceMap[id] == 0);
        require(userId > 0);
        require(userHash.length > 0);
        require(bottomLeft > 0);
        require(topLeft > 0);
        require(topRight > 0);
        require(bottomRight > 0);
        require(bytes(txType).length > 0);
        require(bytes(txId).length > 0);
        require(txTime > 0);
        
        var space = Space({
            id: id,
            userId: userId,
            userHash: userHash,
            bottomLeft: bottomLeft,
            topLeft: topLeft,
            topRight: topRight,
            bottomRight: bottomRight,
            txType: txType,
            txId: txId,
            txTime: txTime,
            created: block.timestamp
        });

        var _index = spaces.push(space) - 1;
        assert(_index >= START_INDEX);
        spaceMap[id] = _index;
        userSpaceLookup[userId].push(id);
        Add();
    }

    function getSpaceByIndex(uint index) external constant returns(
        uint id,
        uint userId,
        bytes userHash,
        uint bottomLeft,
        uint topLeft,
        uint topRight, 
        uint bottomRight,
        string txType,
        string txId, 
        uint txTime,
        uint created) {

        var _index = index + START_INDEX;
        require(spaces.length > _index);
        var space = spaces[_index];
        id = space.id;
        userId = space.userId;
        userHash = space.userHash;
        bottomLeft = space.bottomLeft;
        topLeft = space.topLeft;
        topRight = space.topRight;
        bottomRight = space.bottomRight;
        txType = space.txType;
        txId = space.txId;
        txTime = space.txTime;
        created = space.created;
    }    

    function getSpaceById(uint _id) external constant returns(
        uint id,
        uint userId,
        bytes userHash,
        uint bottomLeft,
        uint topLeft,
        uint topRight, 
        uint bottomRight,
        string txType,
        string txId,
        uint txTime,
        uint created) {

        require(_id > 0);
        id = _id;
        var index = spaceMap[id];
        var space = spaces[index];
        userId = space.userId;
        userHash = space.userHash;
        bottomLeft = space.bottomLeft;
        topLeft = space.topLeft;
        topRight = space.topRight;
        bottomRight = space.bottomRight;
        txType = space.txType;
        txId = space.txId;
        txTime = space.txTime;
        created = space.created;
    }

    function getUserSpaceIds(uint userId) external constant returns(uint[]) {
        require(userId > 0);
        return userSpaceLookup[userId]; 
    }

    function getUserId(uint id) external constant returns(uint) {
        require(id > 0);
        var index = spaceMap[id];
        require(index > 0);
        var space = spaces[index];
        return space.userId; 
    }

    function exists(uint id) public constant returns(bool) {
        require(id > 0);
        return spaceMap[id] != 0;
    }
    
    function spaceCount() public constant returns (uint) {
        return spaces.length - START_INDEX;
    }   
}
