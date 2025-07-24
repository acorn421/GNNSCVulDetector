/*
 * ===== SmartInject Injection Details =====
 * Function      : sellEggs
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **SPECIFIC CHANGES MADE:**
 *    - Added timestamp-dependent bonus logic that triggers when `block.timestamp % 3600 < 300` (first 5 minutes of each hour)
 *    - Introduced a bonus multiplier calculation using `SafeMath.add(sellTime, lastHatch[msg.sender])` as a timing seed
 *    - Made the bonus system stateful by storing sell timestamps in `lastHatch` for future bonus calculations
 *    - The bonus multiplier ranges from 1-10x based on the timing seed modulo operation
 * 
 * 2. **MULTI-TRANSACTION EXPLOITATION MECHANISM:**
 *    - **Transaction 1**: Attacker calls `sellEggs()` during a non-bonus period to establish their `lastHatch` timestamp in state
 *    - **Transaction 2**: Attacker waits for a favorable block timestamp (first 5 minutes of an hour) where the timing seed calculation (`sellTime + lastHatch[msg.sender] % 10`) will produce a high bonus multiplier
 *    - **Transaction 3+**: Attacker can repeat this pattern, using the previously stored `lastHatch` value to manipulate future bonus calculations
 * 
 * 3. **WHY MULTIPLE TRANSACTIONS ARE REQUIRED:**
 *    - The vulnerability requires **state accumulation** - the `lastHatch` value from previous transactions directly affects future bonus calculations
 *    - An attacker cannot exploit this in a single transaction because they need to first establish a favorable `lastHatch` timestamp in the contract state
 *    - The exploit becomes more powerful over multiple transactions as the attacker can strategically time their sells to maximize the bonus multiplier
 *    - Miners or validators could manipulate block timestamps across multiple blocks to consistently hit the bonus windows
 *    - The stateful nature means each transaction influences the profitability of future transactions
 * 
 * 4. **REALISTIC VULNERABILITY CHARACTERISTICS:**
 *    - Uses `block.timestamp` directly in critical financial calculations
 *    - Implements a "timing bonus" feature that could realistically appear in gaming contracts
 *    - The 5-minute window and hourly cycle mimic common real-world timing mechanisms
 *    - The bonus system encourages repeated interaction, making it attractive to users while being exploitable by sophisticated attackers
 * 
 * This vulnerability demonstrates how timestamp dependence can be exploited across multiple transactions through persistent state manipulation, where each transaction sets up more favorable conditions for future exploitation.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the sell timestamp for future bonus calculations
        uint256 sellTime = now;
        
        // Multi-transaction vulnerability: timestamp-dependent bonus that accumulates
        // Check if seller qualifies for "timing bonus" based on block timestamp patterns
        if (sellTime % 3600 < 300) { // Within first 5 minutes of each hour
            // Bonus increases based on previous sell timing stored in state
            uint256 timingSeed = SafeMath.add(sellTime, lastHatch[msg.sender]);
            uint256 bonusMultiplier = (timingSeed % 10) + 1; // 1-10x multiplier
            
            // Apply timing bonus - vulnerable to timestamp manipulation
            eggValue = SafeMath.mul(eggValue, bonusMultiplier);
            fee = devFee(eggValue);
            
            // Store timing data for future bonus calculations (stateful)
            lastHatch[msg.sender] = sellTime; // Overwrite with sell time instead of now
        } else {
            // Normal flow - still update lastHatch for future bonus potential
            lastHatch[msg.sender] = now;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        claimedEggs[msg.sender]=0;
        marketEggs=SafeMath.add(marketEggs,hasEggs);
        creatorAddress.transfer(fee);
        msg.sender.transfer(SafeMath.sub(eggValue,fee));
    }
    function buyEggs() public payable{
        require(initialized);
        uint256 eggsBought=calculateEggBuy(msg.value,SafeMath.sub(this.balance,msg.value));
        eggsBought=SafeMath.sub(eggsBought,devFee(eggsBought));
        creatorAddress.transfer(devFee(msg.value));
        claimedEggs[msg.sender]=SafeMath.add(claimedEggs[msg.sender],eggsBought);
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