/*
 * ===== SmartInject Injection Details =====
 * Function      : move
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent speed bonus system that tracks consecutive move timing and allows players to move multiple cells based on accumulated speed bonuses. The vulnerability requires multiple transactions to build up the speed bonus and exploits block.timestamp manipulation by miners to gain unfair movement advantages. State variables lastMoveTime and speedBonus persist between transactions, making this a stateful multi-transaction vulnerability where miners can manipulate timestamps to either gain speed bonuses or prevent opponents from getting them.
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
    address support = msg.sender;
    
    uint private seed;

    // ==== ADDED STATE VARIABLES FOR COMPILATION ====
    mapping(address => uint) public lastMoveTime;
    mapping(address => uint) public speedBonus;
    // ==============================================

    event UserPlaced(address user, int x, int y);
    event UserAttacked(address user, address by);
    event UserRemoved(address user);
    
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
        fees();
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store movement timestamp for speed calculations
        uint currentTime = block.timestamp;
        uint timeDiff = currentTime - lastMoveTime[msg.sender];
        
        // Speed bonus for quick consecutive moves (within 60 seconds)
        if (timeDiff < 60 && timeDiff > 0) {
            speedBonus[msg.sender] = speedBonus[msg.sender] + 1;
        } else {
            speedBonus[msg.sender] = 0;
        }
        
        // Apply speed bonus - can move multiple cells if bonus is high enough
        uint moveDistance = 1 + (speedBonus[msg.sender] / 3);
        
        if (dir == 0) {
            moveTo(0, -int(moveDistance));
        } else if (dir == 1) {
            moveTo(int(moveDistance), 0);
        } else if (dir == 2) {
            moveTo(0, int(moveDistance));
        } else {
            moveTo(-int(moveDistance), 0);
        }
        
        lastMoveTime[msg.sender] = currentTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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