/*
 * ===== SmartInject Injection Details =====
 * Function      : sellEggs
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Modified the sellEggs function to introduce a stateful, multi-transaction reentrancy vulnerability by moving critical state updates (claimedEggs reset, lastHatch timestamp, marketEggs increment) AFTER the external transfer calls. This creates a classic reentrancy vulnerability that requires multiple transactions to exploit effectively.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls sellEggs() normally to establish initial state (eggs accumulated, lastHatch set)
 * 
 * 2. **Transaction 2 (Exploit)**: Attacker calls sellEggs() again. During the msg.sender.transfer() call, the attacker's malicious contract reenters sellEggs() because:
 *    - claimedEggs[msg.sender] has NOT been reset to 0 yet
 *    - lastHatch[msg.sender] still contains the old timestamp
 *    - marketEggs has not been updated yet
 *    - This means getMyEggs() will still return the same egg count
 * 
 * 3. **Reentrancy Chain**: The attacker can repeatedly call sellEggs() within the same transaction, each time:
 *    - Getting the same egg count from getMyEggs() (since claimedEggs wasn't reset)
 *    - Receiving payment for the same eggs multiple times
 *    - Only after all reentrant calls complete do the state updates execute
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability exploits the time-based egg accumulation mechanism where eggs accumulate between lastHatch timestamps. The attacker needs prior transactions to accumulate eggs.
 * 
 * 2. **Temporal Dependencies**: The getMyEggs() function depends on both claimedEggs and getEggsSinceLastHatch(). The exploit requires established state from previous transactions.
 * 
 * 3. **Market Dynamics**: The calculateEggSell() function depends on marketEggs ratio. Multiple transactions allow the attacker to manipulate market conditions over time.
 * 
 * 4. **Realistic Attack Pattern**: Real attackers would need to:
 *    - Transaction 1: Call getFreeTurtles() to get initial turtles
 *    - Transaction 2: Call hatchEggs() to accumulate eggs over time
 *    - Transaction 3: Execute the reentrancy attack on sellEggs()
 * 
 * This vulnerability requires the attacker to build up state across multiple transactions before the final exploit, making it a realistic multi-transaction reentrancy vulnerability that mirrors real-world attack patterns.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // First external call before critical state updates
        creatorAddress.transfer(fee);
        msg.sender.transfer(SafeMath.sub(eggValue,fee));
        
        // Critical state updates moved after external calls - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        marketEggs=SafeMath.add(marketEggs,hasEggs);
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