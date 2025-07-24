/*
 * ===== SmartInject Injection Details =====
 * Function      : hatchEggs
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the referrer contract after calculating eggsUsed but before updating critical state variables (claimedEggs, lastHatch). This creates a vulnerable window where:
 * 
 * 1. **Multi-Transaction Exploitation Pattern**:
 *    - Transaction 1: User calls hatchEggs() which triggers external call to malicious referrer
 *    - Transaction 2: Malicious referrer re-enters hatchEggs() while state (lastHatch, claimedEggs) is still stale
 *    - The vulnerability exploits the time gap between reading eggs and updating timestamps
 * 
 * 2. **Stateful Vulnerability Mechanics**:
 *    - getMyEggs() depends on lastHatch timestamp and claimedEggs state
 *    - During reentrancy, lastHatch hasn't been updated yet, allowing multiple claims for the same time period
 *    - Each successful reentrancy increases hatcheryShrimp count beyond intended limits
 *    - The accumulated state changes persist between transactions
 * 
 * 3. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the referrer to be a contract that can call back into hatchEggs()
 *    - The first transaction establishes the referral relationship and triggers the callback
 *    - Subsequent reentrant calls exploit the stale state before it gets updated
 *    - Single transaction exploitation is impossible due to the need for external contract interaction
 * 
 * 4. **Realistic Integration**:
 *    - The external call appears as a legitimate notification mechanism for referrers
 *    - Uses low-level call() to avoid reverting on failures
 *    - Fits naturally within existing referral system logic
 *    - Maintains original function behavior while introducing the vulnerability
 * 
 * The vulnerability allows attackers to drain more eggs than intended by repeatedly calling hatchEggs() through reentrancy before the lastHatch timestamp is updated, effectively claiming eggs for the same time period multiple times across different transactions.
 */
pragma solidity ^0.4.18; // solhint-disable-line

/*
*Come Farm some Ether Tards with me at www.tardfarmer.club
*/

contract Tardis{
    //uint256 EGGS_PER_SHRIMP_PER_SECOND=1;
    uint256 public EGGS_TO_HATCH_1SHRIMP=86400;//for final version should be seconds in a day
    uint256 public STARTING_SHRIMP=69;
    uint256 PSN=10000;
    uint256 PSNH=5000;
    bool public initialized=false;
    address public ceoAddress;
    mapping (address => uint256) public hatcheryShrimp;
    mapping (address => uint256) public claimedEggs;
    mapping (address => uint256) public lastHatch;
    mapping (address => address) public referrals;
    uint256 public marketEggs;
    function Tardis() public{
        ceoAddress=msg.sender;
    }
    function hatchEggs(address ref) public{
        require(initialized);
        if(referrals[msg.sender]==0 && referrals[msg.sender]!=msg.sender){
            referrals[msg.sender]=ref;
        }
        uint256 eggsUsed=getMyEggs();
        uint256 newShrimp=SafeMath.div(eggsUsed,EGGS_TO_HATCH_1SHRIMP);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify referrer about the hatching event before state updates
        if(referrals[msg.sender] != address(0) && referrals[msg.sender] != msg.sender) {
            // External call to referrer contract - potential reentrancy point
            (bool success, ) = referrals[msg.sender].call(abi.encodeWithSignature("onHatchNotification(address,uint256)", msg.sender, eggsUsed));
            // Continue execution regardless of call success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        hatcheryShrimp[msg.sender]=SafeMath.add(hatcheryShrimp[msg.sender],newShrimp);
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        
        //send referral eggs
        claimedEggs[referrals[msg.sender]]=SafeMath.add(claimedEggs[referrals[msg.sender]],SafeMath.div(eggsUsed,5));
        
        //boost market to nerf shrimp hoarding
        marketEggs=SafeMath.add(marketEggs,SafeMath.div(eggsUsed,10));
    }
    function sellEggs() public{
        require(initialized);
        uint256 hasEggs=getMyEggs();
        uint256 eggValue=calculateEggSell(hasEggs);
        uint256 fee=devFee(eggValue);
        hatcheryShrimp[msg.sender]=SafeMath.mul(SafeMath.div(hatcheryShrimp[msg.sender],10),9);
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        marketEggs=SafeMath.add(marketEggs,hasEggs);
        ceoAddress.transfer(fee);
        msg.sender.transfer(SafeMath.sub(eggValue,fee));
    }
    function buyEggs() public payable{
        require(initialized);
        uint256 eggsBought=calculateEggBuy(msg.value,SafeMath.sub(this.balance,msg.value));
        eggsBought=SafeMath.sub(eggsBought,devFee(eggsBought));
        ceoAddress.transfer(devFee(msg.value));
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
        return SafeMath.div(SafeMath.mul(amount,5),100);
    }
    function seedMarket(uint256 eggs) public payable{
        require(marketEggs==0);
        initialized=true;
        marketEggs=eggs;
    }
    function getFreeShrimp() public{
        require(initialized);
        require(hatcheryShrimp[msg.sender]==0);
        lastHatch[msg.sender]=now;
        hatcheryShrimp[msg.sender]=STARTING_SHRIMP;
    }
    function getBalance() public view returns(uint256){
        return this.balance;
    }
    function getMyShrimp() public view returns(uint256){
        return hatcheryShrimp[msg.sender];
    }
    function getMyEggs() public view returns(uint256){
        return SafeMath.add(claimedEggs[msg.sender],getEggsSinceLastHatch(msg.sender));
    }
    function getEggsSinceLastHatch(address adr) public view returns(uint256){
        uint256 secondsPassed=min(EGGS_TO_HATCH_1SHRIMP,SafeMath.sub(now,lastHatch[adr]));
        return SafeMath.mul(secondsPassed,hatcheryShrimp[adr]);
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