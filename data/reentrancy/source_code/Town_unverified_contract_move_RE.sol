/*
 * ===== SmartInject Injection Details =====
 * Function      : move
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Movement Tracking State**: Introduced `movementLimits`, `totalMoves`, and `lastMoveTime` mappings that persist across transactions and create exploitable state dependencies.
 * 
 * 2. **Callback Mechanism**: Added a reward system that makes external calls to `IMovementReward(rewardContract).processReward()` every 5 moves, creating a user-controlled callback point.
 * 
 * 3. **State Update Ordering**: Moved critical state updates (`totalMoves`, `movementLimits`, `lastMoveTime`) to occur AFTER external calls (`fees()` and reward callback), violating the Checks-Effects-Interactions pattern.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1-4**: Attacker makes 4 legitimate moves, accumulating `totalMoves` state
 *    - **Transaction 5**: On the 5th move, the reward callback is triggered
 *    - **During callback**: Malicious reward contract re-enters `move()` before state updates complete
 *    - **Exploitation**: Since `totalMoves` and `movementLimits` haven't been updated yet, the attacker can:
 *      - Bypass movement limits by re-entering before `movementLimits` is decremented
 *      - Make unlimited moves by exploiting the state gap
 *      - Manipulate accumulated rewards through repeated re-entry
 * 
 * 5. **Stateful Requirements**: The vulnerability requires:
 *    - Multiple transactions to build up `totalMoves` counter
 *    - Persistent state across calls for exploitation
 *    - Cannot be exploited in a single transaction without prior state accumulation
 * 
 * The vulnerability is realistic as it mimics common patterns in gaming contracts with reward systems and state tracking, while creating a genuine multi-transaction reentrancy exploit.
 */
pragma solidity ^0.4.25;

contract Town {
    struct Position {
        int x;
        int y;
    }
    
    uint movePrice = 0.001 ether;
    uint attackPrice = 0.005 ether;
    uint spawnPrice = 0.01 ether;
    uint fee = 20;
    uint refFee = 10;

    mapping (address => bool) internal users;
    mapping (address => bool) internal ingame;
    mapping (address => address) public referrers;
    mapping (int => mapping (int => address)) public field;
    mapping (address => Position) public positions;
    
    // Fix: Declare missing mappings
    mapping(address => uint) public movementLimits;
    mapping(address => uint) public totalMoves;
    mapping(address => uint) public lastMoveTime;
    
    // Fix: Declare missing variables
    address public rewardContract;
    
    address support = msg.sender;
    
    uint private seed;
    
    event UserPlaced(address user, int x, int y);
    event UserAttacked(address user, address by);
    event UserRemoved(address user);

    // Fix: Move interface outside the contract as it's not allowed inside in Solidity <0.5.0
}

// Fix: Declare interface for IMovementReward outside the contract
interface IMovementReward {
    function processReward(address user, uint amount) external;
}

contract TownV2 is Town {
    /* Converts uint256 to bytes32 */
    function toBytes(uint256 x) internal pure returns (bytes b) {
        b = new bytes(32);
        assembly {
            mstore(add(b, 32), x)
        }
    }
    
    function random(uint lessThan) internal returns (uint) {
        seed += block.timestamp + uint(msg.sender);
        return uint(sha256(toBytes(uint(blockhash(block.number - 1)) + seed))) % lessThan;
    }
    
    function bytesToAddress(bytes source) internal pure returns (address parsedAddress) {
        assembly {
            parsedAddress := mload(add(source,0x14))
        }
        return parsedAddress;
    }
    
    function requireEmptyCell(int x, int y) internal view {
        require(field[x][y] == 0x0);
    }
    
    function moveTo(int diffX, int diffY) internal {
        Position storage p = positions[msg.sender];
        int _x = p.x + diffX;
        int _y = p.y + diffY;
        requireEmptyCell(_x, _y);
        delete field[p.x][p.y];
        field[_x][_y] = msg.sender;
        positions[msg.sender] = Position(_x, _y);
    }
    
    function removeUserFrom(address user, int x, int y) internal {
        delete ingame[user];
        delete field[x][y];
        delete positions[user];
    }
    
    function tryAttack(int diffX, int diffY) internal returns (address) {
        Position storage p = positions[msg.sender];
        int _x = p.x + diffX;
        int _y = p.y + diffY;
        address enemy = field[_x][_y];
        if (enemy != 0x0) {
            removeUserFrom(enemy, _x, _y);
            msg.sender.transfer(address(this).balance / 2);
            return enemy;
        } else {
            return 0x0;
        }
    }
    
    function fees() internal {
        support.transfer(msg.value * fee / 100);
        if (referrers[msg.sender] != 0x0) {
            referrers[msg.sender].transfer(msg.value * refFee / 100);
        }
    }

    function move(uint8 dir) external payable {
        require(ingame[msg.sender]);
        require(msg.value == movePrice);
        require(dir < 4);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add movement limit tracking for multi-transaction exploitation
        if (movementLimits[msg.sender] == 0) {
            movementLimits[msg.sender] = 3; // Initialize with 3 moves
        }
        require(movementLimits[msg.sender] > 0, "Movement limit exceeded");
        
        // Vulnerable: External call before state updates
        fees();
        
        // Add callback mechanism for accumulated rewards (vulnerable to reentrancy)
        if (totalMoves[msg.sender] > 0 && totalMoves[msg.sender] % 5 == 0) {
            // Reward system - external call to user-controlled contract
            IMovementReward(rewardContract).processReward(msg.sender, totalMoves[msg.sender]);
        }
        
        // State updates happen after external calls (vulnerable window)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (dir == 0) {
            moveTo(0, -1);
        } else if (dir == 1) {
            moveTo(1, 0);
        } else if (dir == 2) {
            moveTo(0, 1);
        } else {
            moveTo(-1, 0);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update state variables after external calls
        totalMoves[msg.sender] += 1;
        movementLimits[msg.sender] -= 1;
        lastMoveTime[msg.sender] = block.timestamp;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit UserPlaced(msg.sender, positions[msg.sender].x, positions[msg.sender].y);
    }
    
    function attack(uint8 dir) external payable {
        require(ingame[msg.sender]);
        require(msg.value == attackPrice);
        require(dir < 4);
        fees();
        address enemy;
        if (dir == 0) {
            enemy = tryAttack(0, -1);
        } else if (dir == 1) {
            enemy = tryAttack(1, 0);
        } else if (dir == 2) {
            enemy = tryAttack(0, 1);
        } else {
            enemy = tryAttack(-1, 0);
        }
        emit UserAttacked(enemy, msg.sender);
        emit UserRemoved(enemy);
    }
    
    function () external payable {
        require(!ingame[msg.sender]);
        require(msg.value == spawnPrice);
        ingame[msg.sender] = true;
        if (!users[msg.sender]) {
            users[msg.sender] = true;
            address referrerAddress = bytesToAddress(bytes(msg.data));
            require(referrerAddress != msg.sender);     
            if (users[referrerAddress]) {
                referrers[msg.sender] = referrerAddress;
            }
        }
        
        fees();
        
        int x = int(random(20)) - 10;
        int y = int(random(20)) - 10;
        
        while (field[x][y] != 0x0) {
            x += int(random(2)) * 2 - 1;
            y += int(random(2)) * 2 - 1;
        }
        
        field[x][y] = msg.sender;
        positions[msg.sender] = Position(x, y);
        
        emit UserPlaced(msg.sender, x, y);
    }
}
