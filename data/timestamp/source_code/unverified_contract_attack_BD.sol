/*
 * ===== SmartInject Injection Details =====
 * Function      : attack
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding timing-based attack mechanics that can be exploited across multiple transactions. The vulnerability requires state variables like `lastAttackTime[msg.sender]` to track timing between calls, and uses `block.timestamp % 10` for attack success calculations. This creates a multi-transaction exploit where attackers can: 1) First call to establish timing state, 2) Wait for favorable timestamp conditions (when `block.timestamp % 10 < 3`), 3) Subsequent calls to exploit timing for guaranteed success and bonus rewards. The vulnerability is realistic as it mimics common gaming mechanics while being genuinely exploitable by miners who can manipulate timestamps or players who can time their transactions strategically.
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

    mapping(address => uint) lastAttackTime; // <--- Added missing declaration
    
    uint private seed;
    
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
        if (dir == 0) {
            moveTo(0, -1);
        } else if (dir == 1) {
            moveTo(1, 0);
        } else if (dir == 2) {
            moveTo(0, 1);
        } else {
            moveTo(-1, 0);
        }
        emit UserPlaced(msg.sender, positions[msg.sender].x, positions[msg.sender].y);
    }
    
    function attack(uint8 dir) external payable {
        require(ingame[msg.sender]);
        require(msg.value == attackPrice);
        require(dir < 4);
        fees();
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent attack cooldown with vulnerable state tracking
        if (lastAttackTime[msg.sender] == 0) {
            lastAttackTime[msg.sender] = block.timestamp;
        }
        
        // Vulnerable time-based attack bonus calculation
        uint timeBonus = 0;
        uint timeSinceLastAttack = block.timestamp - lastAttackTime[msg.sender];
        
        // Critical vulnerability: Using block.timestamp for attack success calculation
        // This creates a multi-transaction exploit where attackers can:
        // 1. First call: Establish timing state
        // 2. Wait for favorable timestamp conditions
        // 3. Subsequent calls: Exploit timing for guaranteed success
        if (timeSinceLastAttack > 0 && (block.timestamp % 10) < 3) {
            timeBonus = 1; // Guaranteed attack success during favorable timestamp windows
        }
        
        // Store current attack timestamp for future vulnerability exploitation
        lastAttackTime[msg.sender] = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Apply timestamp-dependent bonus that affects contract balance distribution
        if (timeBonus > 0 && enemy != 0x0) {
            // Vulnerable: Additional reward based on timestamp manipulation
            msg.sender.transfer(address(this).balance / 4);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
