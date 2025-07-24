/*
 * ===== SmartInject Injection Details =====
 * Function      : addSpace
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external call to a user-controlled contract before the critical state updates. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **State Changes**: The space is already pushed to the `spaces` array, but `spaceMap[id]` is not yet set when the external call occurs
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: User calls addSpace with userHash containing their malicious contract address
 *    - During the external call, the malicious contract can re-enter addSpace with the same ID
 *    - The re-entrant call passes the `require(spaceMap[id] == 0)` check because spaceMap hasn't been updated yet
 *    - This creates multiple spaces with the same ID in the spaces array
 *    - Transaction 2+: The corrupted state (multiple spaces with same ID) can be exploited in subsequent transactions through other functions like getSpaceById
 * 
 * 3. **Stateful Nature**: The vulnerability requires the accumulated state corruption across multiple transactions to be fully exploitable. The first transaction creates the inconsistent state, and subsequent transactions can exploit this corrupted state to cause further damage or extract value.
 * 
 * 4. **Realistic Integration**: The external call is disguised as a "space validation" feature that could realistically exist in production code, making it subtle and believable.
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
  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
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
    emit Stop();
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

    constructor() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to user-controlled contract for "space validation"
        // This call happens BEFORE critical state updates, enabling reentrancy
        if (userHash.length > 32) {
            address validator;
            assembly {
                // First 20 bytes of userHash
                validator := mload(add(userHash, 20))
            }
            require(validator.call(bytes4(keccak256("validateSpace(uint256,uint256)")), id, userId));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        spaceMap[id] = _index;
        userSpaceLookup[userId].push(id);
        emit Add();
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