/*
 * ===== SmartInject Injection Details =====
 * Function      : buyEggs
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
 * Introduced a timestamp dependence vulnerability through a multi-transaction bonus system that relies on block.timestamp for critical calculations. The vulnerability requires multiple state variables (lastPurchaseTime, consecutivePurchases) that persist between transactions and accumulate bonuses based on timing patterns.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added state tracking variables**: `lastPurchaseTime[msg.sender]` and `consecutivePurchases[msg.sender]` that persist between transactions
 * 2. **Implemented time-based consecutive purchase bonus**: Users get 5% bonus per consecutive purchase within 24 hours
 * 3. **Added "golden hours" bonus**: Extra 25% bonus for purchases made during specific hours (every 6 hours)
 * 4. **Used block.timestamp extensively**: Critical logic depends on `block.timestamp` for timing calculations and bonus determinations
 * 
 * **Multi-Transaction Exploitation:**
 * 
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * 1. **Transaction 1**: Initial purchase establishes baseline timing and starts consecutive purchase counter
 * 2. **Transaction 2+**: Subsequent purchases within 24 hours accumulate consecutive bonuses (5% per purchase)
 * 3. **Timing Manipulation**: Attackers can manipulate block.timestamp through miner collusion to:
 *    - Extend the 24-hour window artificially
 *    - Ensure purchases always hit "golden hours" for maximum bonus
 *    - Accumulate maximum consecutive purchase bonuses
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The `consecutivePurchases` counter must be built up over multiple transactions
 * 2. **Timing Windows**: The 24-hour consecutive purchase window requires time passage between transactions
 * 3. **Bonus Compounding**: Maximum exploitation requires multiple purchases to accumulate the full bonus potential
 * 4. **Realistic Usage Pattern**: The vulnerability mimics legitimate user behavior (multiple purchases over time) making it harder to detect
 * 
 * **Exploitation Scenarios:**
 * 
 * - **Miner Collusion**: Miners can manipulate timestamps to ensure all purchases fall within optimal timing windows
 * - **Coordinated Attacks**: Attackers time multiple transactions to maximize bonuses while manipulating block.timestamp
 * - **State Persistence**: The vulnerability leverages persistent state changes across transactions, making it stateful and multi-transaction dependent
 */
pragma solidity ^0.4.18; // solhint-disable-line



contract TurtleFarmer{
    //uint256 EGGS_PER_TURTLE_PER_SECOND=1;
    uint256 public EGGS_TO_HATCH_1TURTLE=86400;//for final version should be seconds in a day
    uint256 public STARTING_TURTLES=300;
    uint256 PSN=10000;
    uint256 PSNH=5000;
    bool public initialized=false;
    address public creatorAddress;
    mapping (address => uint256) public hatcheryTurtles;
    mapping (address => uint256) public claimedEggs;
    mapping (address => uint256) public lastHatch;
    mapping (address => address) public referrals;
    uint256 public marketEggs;
    // ==== FIX START: Add missing mappings for vulnerability logic ====
    mapping (address => uint256) public lastPurchaseTime;
    mapping (address => uint256) public consecutivePurchases;
    // ==== FIX END ====
    function TurtleFarmer() public{
        creatorAddress=msg.sender;
    }
    function hatchEggs(address ref) public{
        require(initialized);
        if(referrals[msg.sender]==0 && referrals[msg.sender]!=msg.sender){
            referrals[msg.sender]=ref;
        }
        uint256 eggsUsed=getMyEggs();
        uint256 newTurtles=SafeMath.div(eggsUsed,EGGS_TO_HATCH_1TURTLE);
        hatcheryTurtles[msg.sender]=SafeMath.add(hatcheryTurtles[msg.sender],newTurtles);
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        
        //send referral eggs
        claimedEggs[referrals[msg.sender]]=SafeMath.add(claimedEggs[referrals[msg.sender]],SafeMath.div(eggsUsed,5));
        
        //boost market to nerf turtle hoarding
        marketEggs=SafeMath.add(marketEggs,SafeMath.div(eggsUsed,10));
    }
    function sellEggs() public{
        require(initialized);
        uint256 hasEggs=getMyEggs();
        uint256 eggValue=calculateEggSell(hasEggs);
        uint256 fee=devFee(eggValue);
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        marketEggs=SafeMath.add(marketEggs,hasEggs);
        creatorAddress.transfer(fee);
        msg.sender.transfer(SafeMath.sub(eggValue,fee));
    }
    function buyEggs() public payable{
        require(initialized);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based purchase bonus system using block.timestamp
        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastPurchase = SafeMath.sub(currentTime, lastPurchaseTime[msg.sender]);
        
        // Initialize first purchase time if not set
        if (lastPurchaseTime[msg.sender] == 0) {
            lastPurchaseTime[msg.sender] = currentTime;
        }
        
        // Accumulate consecutive purchase bonus (resets after 24 hours of inactivity)
        if (timeSinceLastPurchase <= 86400) { // 24 hours
            consecutivePurchases[msg.sender] = SafeMath.add(consecutivePurchases[msg.sender], 1);
        } else {
            consecutivePurchases[msg.sender] = 1;
        }
        
        uint256 eggsBought=calculateEggBuy(msg.value,SafeMath.sub(this.balance,msg.value));
        
        // Apply time-based bonus using block.timestamp calculations
        uint256 bonusMultiplier = SafeMath.mul(consecutivePurchases[msg.sender], 5); // 5% per consecutive purchase
        if (bonusMultiplier > 100) {
            bonusMultiplier = 100; // Cap at 100%
        }
        
        // Additional bonus for purchases made within "golden hours" (every 6 hours)
        uint256 hourOfDay = SafeMath.div(currentTime, 3600) % 24;
        if (hourOfDay % 6 == 0) { // Golden hours: 0, 6, 12, 18
            bonusMultiplier = SafeMath.add(bonusMultiplier, 25);
        }
        
        uint256 timeBonus = SafeMath.div(SafeMath.mul(eggsBought, bonusMultiplier), 100);
        eggsBought = SafeMath.add(eggsBought, timeBonus);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        eggsBought=SafeMath.sub(eggsBought,devFee(eggsBought));
        creatorAddress.transfer(devFee(msg.value));
        claimedEggs[msg.sender]=SafeMath.add(claimedEggs[msg.sender],eggsBought);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update purchase timestamp for future bonus calculations
        lastPurchaseTime[msg.sender] = currentTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    //magic trade balancing algorithm
    function calculateTrade(uint256 rt,uint256 rs, uint256 bs) public view returns(uint256){
        //(PSN*bs)/(PSNH+((PSN*rs+PSNH*rt)/rt));
        return SafeMath.div(SafeMath.mul(PSN,bs),SafeMath.add(PSNH,SafeMath.div(SafeMath.add(SafeMath.mul(PSN,rs),SafeMath.mul(PSNH,rt)),rt)));
    }
    function calculateEggSell(uint256 eggs) public view returns(uint256){
        return calculateTrade(eggs,marketEggs,this.balance);
    }
    function calculateEggBuy(uint256 eth,uint256 contractBalance) public view returns(uint256){
        return calculateTrade(eth,contractBalance,marketEggs);
    }
    function calculateEggBuySimple(uint256 eth) public view returns(uint256){
        return calculateEggBuy(eth,this.balance);
    }
    function devFee(uint256 amount) public view returns(uint256){
        return SafeMath.div(SafeMath.mul(amount,4),100);
    }
    function seedMarket(uint256 eggs) public payable{
        require(marketEggs==0);
        initialized=true;
        marketEggs=eggs;
    }
    function getFreeTurtles() public{
        require(initialized);
        require(hatcheryTurtles[msg.sender]==0);
        lastHatch[msg.sender]=now;
        hatcheryTurtles[msg.sender]=STARTING_TURTLES;
    }
    function getBalance() public view returns(uint256){
        return this.balance;
    }
    function getMyTurtles() public view returns(uint256){
        return hatcheryTurtles[msg.sender];
    }
    function getMyEggs() public view returns(uint256){
        return SafeMath.add(claimedEggs[msg.sender],getEggsSinceLastHatch(msg.sender));
    }
    function getEggsSinceLastHatch(address adr) public view returns(uint256){
        uint256 secondsPassed=min(EGGS_TO_HATCH_1TURTLE,SafeMath.sub(now,lastHatch[adr]));
        return SafeMath.mul(secondsPassed,hatcheryTurtles[adr]);
    }
    function min(uint256 a, uint256 b) private pure returns (uint256) {
        return a < b ? a : b;
    }
}

library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}
