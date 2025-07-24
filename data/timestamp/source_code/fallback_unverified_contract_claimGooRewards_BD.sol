/*
 * ===== SmartInject Injection Details =====
 * Function      : claimGooRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate block timestamps to maximize bonus multipliers. The vulnerability is stateful and multi-transaction because: 1) It requires building up consecutiveClaims state over multiple transactions, 2) The bonus multiplier depends on the timing between claims which persists across transactions, 3) Miners can exploit this by manipulating timestamps within the allowed range to always hit the optimal bonus window, accumulating higher rewards over time through repeated exploitation across multiple blocks.
 */
pragma solidity ^0.4.0;

// *NOT* GOO, just test ERC20 so i can verify EtherDelta works before launch.

interface ERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

contract Goo is ERC20 {
    
    string public constant name  = "ProofOfDev";
    string public constant symbol = "DevToken";
    uint8 public constant decimals = 0;
    uint256 private roughSupply;
    
    // Balances for each player
    mapping(address => uint256) private gooBalance;
    mapping(address => uint256) private lastGooSaveTime;
    mapping(address => mapping(address => uint256)) private allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Bonus reward system with time-based multipliers
    mapping(address => uint256) private lastClaimTime;
    mapping(address => uint256) private consecutiveClaims;
    uint256 private constant BONUS_WINDOW = 86400; // 24 hours in seconds
    // === END FALLBACK INJECTION ===

    // Constructor
    function Goo() public payable {
        roughSupply = 1;
        gooBalance[msg.sender] = 1;
        lastGooSaveTime[msg.sender] = block.timestamp;
    }
    
    function claimGooRewards() public returns (bool) {
        uint256 unclaimedGoo = balanceOfUnclaimedGoo(msg.sender);
        require(unclaimedGoo > 0);
        
        // Apply time-based bonus multiplier
        uint256 bonusMultiplier = 1;
        if (lastClaimTime[msg.sender] > 0) {
            uint256 timeSinceLastClaim = block.timestamp - lastClaimTime[msg.sender];
            
            // Vulnerable: Miners can manipulate timestamp to maximize bonus
            if (timeSinceLastClaim >= BONUS_WINDOW && timeSinceLastClaim <= BONUS_WINDOW + 3600) {
                consecutiveClaims[msg.sender]++;
                bonusMultiplier = 1 + (consecutiveClaims[msg.sender] / 10); // 10% bonus per consecutive claim
            } else if (timeSinceLastClaim > BONUS_WINDOW + 3600) {
                consecutiveClaims[msg.sender] = 0; // Reset streak if too late
            }
        }
        
        uint256 finalReward = unclaimedGoo * bonusMultiplier;
        
        // Update state
        gooBalance[msg.sender] += finalReward;
        lastGooSaveTime[msg.sender] = block.timestamp;
        lastClaimTime[msg.sender] = block.timestamp;
        roughSupply += finalReward;
        
        emit Transfer(address(0), msg.sender, finalReward);
        return true;
    }
    
    function totalSupply() public constant returns(uint256) {
        return roughSupply; // Stored goo (rough supply as it ignores earned/unclaimed goo)
    }
    
    function balanceOf(address player) public constant returns(uint256) {
        return gooBalance[player] + balanceOfUnclaimedGoo(player);
    }
    
    function balanceOfUnclaimedGoo(address player) internal constant returns (uint256) {
        uint256 lastSave = lastGooSaveTime[player];
        if (lastSave > 0 && lastSave < block.timestamp) {
            return (1000 * (block.timestamp - lastSave)) / 100;
        }
        return 0;
    }
    
    function transfer(address recipient, uint256 amount) public returns (bool) {
        require(amount <= gooBalance[msg.sender]);
        
        gooBalance[msg.sender] -= amount;
        gooBalance[recipient] += amount;
        
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }
    
    function transferFrom(address player, address recipient, uint256 amount) public returns (bool) {
        require(amount <= allowed[player][msg.sender] && amount <= gooBalance[player]);
        
        gooBalance[player] -= amount;
        gooBalance[recipient] += amount;
        allowed[player][msg.sender] -= amount;
        
        emit Transfer(player, recipient, amount);
        return true;
    }
    
    function approve(address approvee, uint256 amount) public returns (bool){
        allowed[msg.sender][approvee] = amount;
        emit Approval(msg.sender, approvee, amount);
        return true;
    }
    
    function allowance(address player, address approvee) public constant returns(uint256){
        return allowed[player][approvee];
    }
    
}
