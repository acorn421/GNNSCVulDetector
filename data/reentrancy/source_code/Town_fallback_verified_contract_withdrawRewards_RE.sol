/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This injection adds a reward system with a classic reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability is stateful because it uses the 'withdrawInProgress' mapping to track withdrawal state between transactions. An attacker must: 1) First accumulate rewards through attacks, 2) Call withdrawRewards() which sets withdrawInProgress[attacker] = true, 3) In the reentrancy callback, the attacker can call withdrawRewards() again since the rewards[msg.sender] = 0 update happens after the external call. The vulnerability requires multiple transactions and persistent state changes to be exploited successfully.
 */
pragma solidity ^0.4.25;

contract Town {
    struct Position {
        int x;
        int y;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // Reward system state variables (add these to contract state)
    mapping (address => uint) public rewards;
    mapping (address => bool) public withdrawInProgress;
    
    // Function to accumulate rewards for players
    function addReward(address player, uint amount) internal {
        rewards[player] += amount;
    }
    
    // Vulnerable withdrawal function with reentrancy - requires multiple transactions
    function withdrawRewards() external {
        require(ingame[msg.sender], "Must be in game");
        require(rewards[msg.sender] > 0, "No rewards to withdraw");
        require(!withdrawInProgress[msg.sender], "Withdrawal in progress");
        
        // Mark withdrawal as in progress (stateful change)
        withdrawInProgress[msg.sender] = true;
        
        uint reward = rewards[msg.sender];
        
        // Vulnerable external call before state update
        // This allows reentrancy in subsequent transactions
        if (msg.sender.call.value(reward)()) {
            // State update happens after external call - classic reentrancy
            rewards[msg.sender] = 0;
            withdrawInProgress[msg.sender] = false;
        } else {
            withdrawInProgress[msg.sender] = false;
            revert("Transfer failed");
        }
    }
    
    // Function to check if withdrawal is safe (used in multi-tx attack)
    function canWithdraw() external view returns (bool) {
        return rewards[msg.sender] > 0 && !withdrawInProgress[msg.sender];
    }
    
    // Modified attack function to give rewards (integrates with existing contract)
    function attackWithReward(uint8 dir) external payable {
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
        
        // Add reward for successful attack
        if (enemy != 0x0) {
            addReward(msg.sender, attackPrice / 2);
        }
        
        emit UserAttacked(enemy, msg.sender);
        emit UserRemoved(enemy);
    }
    // === END FALLBACK INJECTION ===

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
