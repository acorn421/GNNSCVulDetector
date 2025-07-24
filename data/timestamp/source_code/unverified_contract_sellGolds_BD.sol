/*
 * ===== SmartInject Injection Details =====
 * Function      : sellGolds
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent market bonus mechanism that creates a stateful, multi-transaction vulnerability. The vulnerability works by:
 * 
 * 1. **Timestamp Window Dependency**: The bonus is only active during specific 5-minute windows every hour (when block.timestamp % 3600 < 300), creating predictable timing windows.
 * 
 * 2. **Stateful Accumulation**: The bonus calculation depends on the time difference between the current block.timestamp and the user's lastCollect timestamp, which is stored in contract state and persists between transactions.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Setup Phase**: An attacker must first call sellGolds() or other functions that update lastCollect[msg.sender] to establish a baseline timestamp
 *    - **Timing Phase**: The attacker then waits for the optimal timing window and calls sellGolds() again when block.timestamp % 3600 < 300
 *    - **Exploitation Phase**: By manipulating the timing between transactions and potentially influencing block timestamps (if they're a miner), attackers can maximize the marketBonus
 * 
 * 4. **State Persistence**: The lastCollect[msg.sender] state variable persists between transactions, enabling the vulnerability to accumulate value based on elapsed time between calls.
 * 
 * 5. **Realistic Vulnerability**: This appears as a legitimate "market activity bonus" feature but creates timestamp manipulation opportunities where miners can influence when the bonus windows occur and users can game the system by timing their sells strategically across multiple transactions.
 */
pragma solidity ^0.4.18; // solhint-disable-line

contract SwordMaster{    
    uint256 public GOLD_TO_COLLECT_1SWORD=86400;
    uint256 public SECONDS_OF_DAY=86400;
    uint256 public STARTING_SWORD=300;
    uint256 public MIN_GOLD_TO_UPGRADE = 300;
    uint256 PSN=10000;
    uint256 PSNH=5000;
    bool public initialized=false;
    address public ceoAddress;
    mapping (address => uint256) public swordLevel;
    mapping (address => uint256) public claimedGolds;
    mapping (address => uint256) public lastCollect;
    mapping (address => address) public referrals;
    uint256 public marketGolds;
    function SwordMaster() public{
        ceoAddress=msg.sender;
    }
    function upgradeSword(address ref) public{
        require(initialized);
        if(referrals[msg.sender]==0 && msg.sender!=ref){
            referrals[msg.sender]=ref;
        }
        uint256 goldUsed=getMyGolds();
        uint256 newGold=SafeMath.div(goldUsed,GOLD_TO_COLLECT_1SWORD);
        uint256 remainGold = newGold % MIN_GOLD_TO_UPGRADE;
        newGold = SafeMath.sub(newGold,remainGold);
        if(newGold <=0){
            return;
        } // upgrade failed
        swordLevel[msg.sender]=SafeMath.add(swordLevel[msg.sender],newGold);
        claimedGolds[msg.sender]=SafeMath.mul(remainGold,GOLD_TO_COLLECT_1SWORD);
        lastCollect[msg.sender]=now;
        
        //send referral gold
        claimedGolds[referrals[msg.sender]]=SafeMath.add(claimedGolds[referrals[msg.sender]],SafeMath.div(newGold * GOLD_TO_COLLECT_1SWORD,5));
        
        //boost market to nerf sword hoarding
        marketGolds=SafeMath.add(marketGolds,SafeMath.div(newGold * GOLD_TO_COLLECT_1SWORD,10));
    }
    function sellGolds() public{
        require(initialized);
        uint256 hasGolds=getMyGolds();
        uint256 goldValue=calculateGoldSell(hasGolds);
        uint256 fee=devFee(goldValue);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Introduce timestamp-based market bonus that accumulates over time
        uint256 marketBonus = 0;
        if (block.timestamp % 3600 < 300) { // 5-minute window every hour
            // Calculate accumulated market activity bonus based on recent selling patterns
            uint256 recentActivity = SafeMath.sub(block.timestamp, lastCollect[msg.sender]);
            if (recentActivity > 0) {
                marketBonus = SafeMath.div(SafeMath.mul(goldValue, recentActivity), 86400); // Daily scaling
                if (marketBonus > SafeMath.div(goldValue, 10)) {
                    marketBonus = SafeMath.div(goldValue, 10); // Cap at 10% bonus
                }
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        claimedGolds[msg.sender]=0;
        lastCollect[msg.sender]=now;
        marketGolds=SafeMath.add(marketGolds,hasGolds);
        ceoAddress.transfer(fee);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        msg.sender.transfer(SafeMath.sub(SafeMath.add(goldValue, marketBonus), fee));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    function buyGolds() public payable{
        require(initialized);
        uint256 goldsBought=calculateGoldBuy(msg.value,SafeMath.sub(address(this).balance,msg.value));
        goldsBought=SafeMath.sub(goldsBought,devFee(goldsBought));
        ceoAddress.transfer(devFee(msg.value));
        claimedGolds[msg.sender]=SafeMath.add(claimedGolds[msg.sender],goldsBought);
    }
    //magic trade balancing algorithm
    function calculateTrade(uint256 rt,uint256 rs, uint256 bs) public view returns(uint256){
        //(PSN*bs)/(PSNH+((PSN*rs+PSNH*rt)/rt));
        return SafeMath.div(SafeMath.mul(PSN,bs),SafeMath.add(PSNH,SafeMath.div(SafeMath.add(SafeMath.mul(PSN,rs),SafeMath.mul(PSNH,rt)),rt)));
    }
    function calculateGoldSell(uint256 golds) public view returns(uint256){
        return calculateTrade(golds,marketGolds,address(this).balance);
    }
    function calculateGoldBuy(uint256 eth,uint256 contractBalance) public view returns(uint256){
        return calculateTrade(eth,contractBalance,marketGolds);
    }
    function calculateGoldBuySimple(uint256 eth) public view returns(uint256){
        return calculateGoldBuy(eth,address(this).balance);
    }
    function devFee(uint256 amount) public pure returns(uint256){
        return SafeMath.div(SafeMath.mul(amount,4),100);
    }
    function seedMarket(uint256 golds) public payable{
        require(marketGolds==0);
        initialized=true;
        marketGolds=golds;
    }
    function getFreeSword() public{
        require(initialized);
        require(swordLevel[msg.sender]==0);
        lastCollect[msg.sender]=now;
        swordLevel[msg.sender]=STARTING_SWORD;
    }
    function getBalance() public view returns(uint256){
        return address(this).balance;
    }
    function getMySword() public view returns(uint256){
        return swordLevel[msg.sender];
    }
    function getMyGolds() public view returns(uint256){
        return SafeMath.add(claimedGolds[msg.sender],getGoldsSinceLastCollect(msg.sender));
    }
    function getGoldsSinceLastCollect(address adr) public view returns(uint256){
        uint256 secondsPassed=min(SECONDS_OF_DAY,SafeMath.sub(now,lastCollect[adr]));
        return SafeMath.mul(secondsPassed,swordLevel[adr]);
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