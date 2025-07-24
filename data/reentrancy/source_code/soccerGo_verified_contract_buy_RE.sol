/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability creates a stateful, multi-transaction reentrancy attack that requires multiple function calls to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added withdrawal tracking state**: `pendingWithdrawals[msg.sender]` accumulates winnings across multiple games
 * 2. **Introduced threshold-based payout**: Only pays out when accumulated winnings reach 0.1 ether
 * 3. **Violated Checks-Effects-Interactions**: External call (`msg.sender.transfer()`) occurs before state updates
 * 4. **Added persistent state variables**: `totalWithdrawn[msg.sender]` and `gamesPlayed[msg.sender]` for tracking
 * 5. **Moved `gameId++` after external call**: Game state updates happen after potential reentrancy
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1-N**: Attacker plays multiple games to accumulate `pendingWithdrawals[attacker]` to reach 0.1 ether threshold
 * 2. **Transaction N+1**: When threshold is reached, `transfer()` is called, triggering attacker's fallback function
 * 3. **Reentrancy**: Attacker's fallback calls `buy()` again before `pendingWithdrawals[attacker] = 0` executes
 * 4. **State Exploitation**: The accumulated withdrawal amount is still available for re-extraction
 * 5. **Multiple Extractions**: Attacker can drain funds multiple times using the same accumulated pending withdrawal
 * 
 * **Why Multiple Transactions Are Required:**
 * - **State Accumulation**: Attacker must first build up pending withdrawals across multiple games
 * - **Threshold Dependency**: The vulnerability only triggers when accumulated winnings reach 0.1 ether
 * - **Persistent State Exploitation**: The attack leverages state that persists between transactions
 * - **Sequential Dependency**: Each transaction builds upon the state from previous transactions
 * 
 * This creates a realistic vulnerability where an attacker must first legitimately play the game multiple times to accumulate winnings, then exploit the reentrancy when the payout threshold is reached.
 */
pragma solidity ^0.4.20;

// v.1.0.0  2018.04.02
contract soccerGo {
    address private owner;
    mapping (address => bool) private admins;
    
    uint256 gameId = 0;
    address callAddr = 0x0;
    
    event showPlayerAddress(address);
    event showPlayerBet(uint256);
    event showBetLeft(uint256);
    event showBetRight(uint256);
    event showResult(uint256);
    event showCount(uint256);
    event showTimeStamp(uint256);
    event showWinValue(uint256);
    
    // Win limit
    uint[] private slot_limit;
    
    // Dev fee
    uint256 fee = 99;

    // Additional state for buy() logic
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public totalWithdrawn;
    mapping(address => uint256) public gamesPlayed;
    
    // Slot 1~10 win limit settings
    function SetLimit(uint _slot, uint win_limit) onlyAdmins() public {
        require(_slot > 0 && _slot < 12);
        slot_limit[_slot - 1] = win_limit;
    }
    
    constructor() public {
        owner = msg.sender;
        admins[owner] = true;
        
        // RTP 97% ~ 98%
        slot_limit.length = 11;
        slot_limit[0] = 1170;
        slot_limit[1] = 611;
        slot_limit[2] = 416;
        slot_limit[3] = 315;
        slot_limit[4] = 253;
        slot_limit[5] = 212;
        slot_limit[6] = 182;
        slot_limit[7] = 159;
        slot_limit[8] = 141;
        slot_limit[9] = 127;
        slot_limit[10] = 115;
    }
    
    function contractBalance() public view returns (uint256) {
        return this.balance;
    }
    
    // Bet limit
    uint256 private min_value = 0.1 ether;
    uint256 private max_value = 0.3 ether;
    
    // SetBetLimit
    function setBetLimit(uint256 min, uint256 max) public onlyAdmins() {
        uint256 base_bet = 0.1 ether;
        min_value = base_bet * min;
        max_value = base_bet * max;
    }
    
    function setCalleeContract(address _caller) public onlyAdmins() {
        callAddr = _caller;
    }
    
    function playTypes(uint _slot_count) internal returns (uint) {
        return (slot_limit[_slot_count - 1]);
    }
    
    function getRandom(address _call) internal returns(uint) {
        Callee c = Callee(_call);
        return c.random(contractBalance(), msg.value, msg.sender);
    }
    
    function setDevfee(uint256 _value) internal onlyAdmins() {
        fee = _value;
    }
    
    function buy(uint256 _left, uint256 _right)
    public
    payable
    {
        require(_left >= 1 && _left <= 13);
        require(_right >= 1 && _right <= 13);
        require(_right - _left >= 1);
        require(msg.value >= min_value);
        require(msg.value <= max_value);
        
        uint256 betValue = msg.value;
        uint256 result = getRandom(callAddr);
        uint256 types = playTypes(_right - _left - 1);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        uint256 winValue = 0;
        
        if (result > _left && result < _right) {
            winValue = betValue * types / 100;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            uint256 payout = (winValue * fee) / 100;
            
            // Record pending withdrawal for delayed payout system
            pendingWithdrawals[msg.sender] += payout;
            
            // Check if player has accumulated enough for instant payout
            if (pendingWithdrawals[msg.sender] >= 0.1 ether) {
                uint256 withdrawAmount = pendingWithdrawals[msg.sender];
                // External call before state update - vulnerable to reentrancy
                msg.sender.transfer(withdrawAmount);
                // State update after external call
                pendingWithdrawals[msg.sender] = 0;
                totalWithdrawn[msg.sender] += withdrawAmount;
            }
        }
        
        // Game state updated after potential external call
        gameId++;
        gamesPlayed[msg.sender]++;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        showPlayerAddress(msg.sender);
        showPlayerBet(betValue);
        showBetLeft(_left);
        showBetRight(_right);
        showResult(result);
        showCount(gameId);
        showTimeStamp(now);
        showWinValue(winValue);
    }
    
    /* Depoit */
    function() payable public { }
    
    /* Withdraw */
    function withdrawAll() onlyOwner() 
    public 
    {
        owner.transfer(this.balance);
    }

    function withdrawAmount(uint256 _amount) onlyOwner() 
    public 
    {
        uint256 value = 1.0 ether;
        owner.transfer(_amount * value);
    }
    
    /* Modifiers */
    modifier onlyOwner() 
    {
        require(owner == msg.sender);
        _;
    }

    modifier onlyAdmins() 
    {
        require(admins[msg.sender]);
        _;
    }
  
    /* Owner */
    function setOwner (address _owner) onlyOwner() 
    public 
    {
        owner = _owner;
    }
    
    function addAdmin (address _admin) onlyOwner() 
    public 
    {
        admins[_admin] = true;
    }

    function removeAdmin (address _admin) onlyOwner() 
    public 
    {
        delete admins[_admin];
    }
}


contract Callee {
    function random(uint256 _balance, uint256 _value, address _player) returns(uint);
}
