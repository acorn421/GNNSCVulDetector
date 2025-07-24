/*
 * ===== SmartInject Injection Details =====
 * Function      : sellEggs
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Tracking**: Introduced `pendingWithdrawals` and `withdrawalCooldown` mappings that persist across transactions
 * 2. **Vulnerable External Call**: Replaced `msg.sender.transfer()` with `msg.sender.call.value()()` which allows reentrancy
 * 3. **State Corruption Window**: The `pendingWithdrawals` is updated before the external call, creating a window for manipulation
 * 4. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Attacker calls `sellEggs()`, which triggers reentrancy during the call.value()
 *    - **During Reentrancy**: Attacker can call `sellEggs()` again, causing `pendingWithdrawals` to accumulate without being cleared
 *    - **Transaction 2+**: Subsequent legitimate calls would process inflated withdrawal amounts
 *    - **Profit**: The accumulated pending withdrawals exceed the actual eggs/value calculated
 * 
 * 5. **Why Multi-Transaction Required**:
 *    - The vulnerability requires building up state through multiple reentrancy calls
 *    - Initial transaction must have sufficient eggs/shrimp (requiring prior game participation)
 *    - The pendingWithdrawals accumulation persists across transaction boundaries
 *    - Exploitation requires coordinated sequence: setup → reentrancy → state corruption → profit extraction
 * 
 * 6. **Realistic Integration**: The cooldown and pending withdrawal mechanisms appear as legitimate features for preventing abuse, making the vulnerability subtle and realistic.
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
        hatcheryShrimp[msg.sender]=SafeMath.add(hatcheryShrimp[msg.sender],newShrimp);
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        
        //send referral eggs
        claimedEggs[referrals[msg.sender]]=SafeMath.add(claimedEggs[referrals[msg.sender]],SafeMath.div(eggsUsed,5));
        
        //boost market to nerf shrimp hoarding
        marketEggs=SafeMath.add(marketEggs,SafeMath.div(eggsUsed,10));
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingWithdrawals;
    mapping (address => uint256) public withdrawalCooldown;
    
    function sellEggs() public{
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(initialized);
        uint256 hasEggs=getMyEggs();
        uint256 eggValue=calculateEggSell(hasEggs);
        uint256 fee=devFee(eggValue);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // State update: Record pending withdrawal before external calls
        pendingWithdrawals[msg.sender]=SafeMath.add(pendingWithdrawals[msg.sender],SafeMath.sub(eggValue,fee));
        withdrawalCooldown[msg.sender]=now + 300; // 5 minute cooldown
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        hatcheryShrimp[msg.sender]=SafeMath.mul(SafeMath.div(hatcheryShrimp[msg.sender],10),9);
        claimedEggs[msg.sender]=0;
        lastHatch[msg.sender]=now;
        marketEggs=SafeMath.add(marketEggs,hasEggs);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External calls that enable reentrancy
        ceoAddress.transfer(fee);
        
        // Vulnerable external call - allows reentrancy into sellEggs again
        if(msg.sender.call.value(SafeMath.sub(eggValue,fee))()) {
            // Only clear pending withdrawal after successful transfer
            pendingWithdrawals[msg.sender]=0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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