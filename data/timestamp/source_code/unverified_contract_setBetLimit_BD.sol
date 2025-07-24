/*
 * ===== SmartInject Injection Details =====
 * Function      : setBetLimit
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **VULNERABILITY ANALYSIS:**
 * 
 * **1. Specific Changes Made:**
 * - Added timestamp-dependent multipliers using `block.timestamp % 10` and `block.number % 5`
 * - Applied these multipliers to the bet limit calculations, making them predictable based on block properties
 * - Added conditional logic that swaps values and adds timestamp-based adjustments when limits are invalid
 * - The state variables `min_value` and `max_value` now depend on block properties, creating timestamp dependence
 * 
 * **2. Multi-Transaction Exploitation:**
 * 
 * **Transaction 1 - Reconnaissance:**
 * - Attacker calls `setBetLimit()` or observes admin calls to understand current timestamp patterns
 * - Studies how `block.timestamp % 10` and `block.number % 5` affect the limit calculations
 * - Identifies favorable timestamp ranges where multipliers create advantageous bet limits
 * 
 * **Transaction 2 - Timing Attack:**
 * - Attacker (if admin) or miner manipulates timing to call `setBetLimit()` when:
 *   - `block.timestamp % 10` is low (reducing min_value significantly)
 *   - `block.number % 5` is high (increasing max_value significantly)
 * - This creates a wide betting range with very low minimum bets
 * 
 * **Transaction 3 - Exploitation:**
 * - In subsequent `buy()` transactions, attacker exploits the manipulated bet limits
 * - Can place very small bets due to reduced min_value while having high max_value ceiling
 * - The timestamp-dependent swap logic can create additional manipulation opportunities
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Dependency:** The vulnerability requires persistent state changes to `min_value` and `max_value` that affect future betting transactions. These state variables are used in the `buy()` function's require statements.
 * 
 * **Timing Coordination:** Exploitation requires:
 * 1. Setting limits at specific timestamp/block ranges (Transaction 1)
 * 2. Waiting for or manipulating subsequent block properties (Transaction 2+)
 * 3. Exploiting the favorable limits in betting transactions (Transaction 3+)
 * 
 * **Predictable Patterns:** The modulo operations create predictable cycles that can be exploited over multiple blocks, requiring attackers to observe patterns across multiple transactions and time their exploitation accordingly.
 * 
 * **Cross-Function Impact:** The timestamp-dependent limits set in `setBetLimit()` directly affect validation in `buy()` function calls, requiring separate transactions to first manipulate limits then exploit them in gambling operations.
 * 
 * This creates a realistic vulnerability where admins or miners can manipulate block properties to create favorable betting conditions that persist across multiple transactions, typical of real-world timestamp dependence vulnerabilities in gambling contracts.
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
    
    // Slot 1~10 win limit settings
    function SetLimit(uint _slot, uint win_limit) onlyAdmins() public {
        require(_slot > 0 && _slot < 12);
        slot_limit[_slot - 1] = win_limit;
    }
    
    function soccerGo() public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for time-based limit adjustments
        uint256 timeMultiplier = (block.timestamp % 10) + 1;
        uint256 blockFactor = (block.number % 5) + 1;
        
        // Apply timestamp-dependent multipliers to bet limits
        min_value = (base_bet * min * timeMultiplier) / 10;
        max_value = (base_bet * max * blockFactor) / 5;
        
        // Store the timestamp for future reference in subsequent calls
        if (min_value > max_value) {
            // Swap values if timestamp created invalid range
            uint256 temp = min_value;
            min_value = max_value;
            max_value = temp + (block.timestamp % 3) * 0.01 ether;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        uint256 winValue = 0;
        gameId++;
        
        if (result > _left && result < _right) {
            winValue = betValue * types / 100;
            msg.sender.transfer((winValue * fee) / 100);
        }

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