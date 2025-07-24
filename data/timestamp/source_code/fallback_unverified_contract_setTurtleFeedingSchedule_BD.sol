/*
 * ===== SmartInject Injection Details =====
 * Function      : setTurtleFeedingSchedule
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The exploit sequence is: 1) User calls setTurtleFeedingSchedule() to set up feeding schedule, 2) User calls upgradeToPremiumFeeder() to become premium feeder, 3) User calls feedTurtles() multiple times to accumulate timestamp-based bonuses. The vulnerability lies in the feedTurtles() function which uses 'now' (block timestamp) for bonus calculation, allowing miners to manipulate timestamps to gain unfair advantages. The stateful nature requires the user to first set up feeding schedule, upgrade to premium, and then exploit the timestamp-based bonus system across multiple transactions.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables and functions were added as part of the fallback injection
    mapping (address => uint256) public feedingSchedule;
    mapping (address => uint256) public lastFeeding;
    mapping (address => bool) public premiumFeeder;

    function TurtleFarmer() public{
        creatorAddress=msg.sender;
    }

    function setTurtleFeedingSchedule(uint256 feedingInterval) public {
        require(initialized);
        require(hatcheryTurtles[msg.sender] > 0);
        feedingSchedule[msg.sender] = feedingInterval;
        lastFeeding[msg.sender] = now;
    }

    function feedTurtles() public {
        require(initialized);
        require(feedingSchedule[msg.sender] > 0);
        require(now >= lastFeeding[msg.sender] + feedingSchedule[msg.sender]);
        
        uint256 turtleCount = hatcheryTurtles[msg.sender];
        uint256 bonusEggs = SafeMath.mul(turtleCount, 100);
        
        // Premium feeders get timestamp-based bonuses
        if (premiumFeeder[msg.sender]) {
            // Vulnerable: Uses block timestamp for bonus calculation
            uint256 timestampBonus = SafeMath.div(now, 3600); // Hours since epoch
            bonusEggs = SafeMath.add(bonusEggs, SafeMath.mul(timestampBonus, 10));
        }
        
        claimedEggs[msg.sender] = SafeMath.add(claimedEggs[msg.sender], bonusEggs);
        lastFeeding[msg.sender] = now;
    }

    function upgradeToPremiumFeeder() public payable {
        require(initialized);
        require(msg.value >= 0.1 ether);
        require(hatcheryTurtles[msg.sender] > 0);
        
        premiumFeeder[msg.sender] = true;
        creatorAddress.transfer(msg.value);
    }
    // === END FALLBACK INJECTION ===

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
