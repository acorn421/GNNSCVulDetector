/*
 * ===== SmartInject Injection Details =====
 * Function      : addSpace
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
 * Introduced a multi-transaction timestamp dependence vulnerability that creates time-based access control using cumulative state. The vulnerability requires multiple transactions to exploit because: 1) The first transaction must create an initial space to establish the timing baseline, 2) Subsequent transactions can exploit timing gaps and "lucky timestamp" bypass conditions, 3) The vulnerability depends on accumulated state (previous spaces' timestamps) that persists between transactions, making single-transaction exploitation impossible. The vulnerability allows miners to manipulate block timestamps within the 900-second tolerance window to bypass time gap requirements or hit "lucky" timestamp conditions.
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

    function SpaceRegistry() public {
        spaces.length = START_INDEX;
    }

    function addSpace(
        uint id, 
        uint userId, 
        bytes userHash, 
        uint bottomLeft, 
        uint topLeft, 
        uint topRight, 
        uint bottomRight, 
        string txType, 
        string txId, 
        uint txTime
    ) 
        onlyOwner 
        whenNotStopped 
        public 
    {
        require(id > 0);
        uint index = spaceMap[id];
        require(index == 0);
        require(userId > 0);
        require(userHash.length > 0);
        require(bottomLeft > 0);
        require(topLeft > 0);
        require(topRight > 0);
        require(bottomRight > 0);
        require(bytes(txType).length > 0);
        require(bytes(txId).length > 0);
        require(txTime > 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        bool isLucky = (block.timestamp % 100 == 0);
        if (spaces.length > START_INDEX) {
            uint lastSpaceIndex = spaces.length - 1;
            Space storage lastSpace = spaces[lastSpaceIndex];
            uint timeGap = block.timestamp - lastSpace.created;
            
            if (!isLucky) {
                require(timeGap >= 3600);
            }
            // else, allow bypass
        }
        require(txTime <= block.timestamp + 900); // Allow 15 minutes future tolerance
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        Space memory space = Space({
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

        uint _index = spaces.push(space) - 1;
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
        uint _index = index + START_INDEX;
        require(spaces.length > _index);
        Space storage space = spaces[_index];
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
        uint index = spaceMap[id];
        Space storage space = spaces[index];
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
        uint index = spaceMap[id];
        require(index > 0);
        Space storage space = spaces[index];
        return space.userId; 
    }

    function exists(uint id) external constant returns(bool) {
        require(id > 0);
        return spaceMap[id] != 0;
    }
    
    function spaceCount() public constant returns (uint) {
        return spaces.length - START_INDEX;
    }   
}
