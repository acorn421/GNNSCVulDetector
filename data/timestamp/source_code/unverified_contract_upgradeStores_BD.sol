/*
 * ===== SmartInject Injection Details =====
 * Function      : upgradeStores
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based bonus system. The vulnerability includes:
 * 
 * 1. **Hour-based bonuses**: Users get 2x rewards during "night hours" (8 PM - 4 AM) based on block.timestamp
 * 2. **Streak multipliers**: Consecutive upgrades during bonus hours provide 6x total rewards
 * 3. **Persistent state tracking**: lastUpgrade timestamp is used to determine streak eligibility across transactions
 * 4. **Referral bonus amplification**: Time-based bonuses also amplify referral rewards
 * 
 * **Multi-Transaction Exploitation Path:**
 * - Transaction 1: Attacker calls upgradeStores() during non-bonus hours to establish lastUpgrade timestamp
 * - Transaction 2: Attacker (or colluding miner) manipulates block.timestamp to fall within bonus hours AND ensures it appears consecutive to previous upgrade
 * - Transaction 3: Attacker gains 6x reward multiplier (2x for bonus hour × 3x for streak)
 * - Transaction 4+: Attacker can repeat the pattern to continuously exploit the streak system
 * 
 * **Why Multi-Transaction Required:**
 * - Streak calculation depends on lastUpgrade state from previous transaction
 * - Cannot manipulate both current and previous timestamps in single transaction
 * - Bonus accumulation requires building up the streak state over multiple calls
 * - Each transaction modifies persistent state that affects future exploitation potential
 * 
 * The vulnerability is realistic as it mimics common gamification patterns in DeFi but fails to account for timestamp manipulation possibilities.
 */
pragma solidity ^0.4.18; // solhint-disable-line



contract ToyCo{
    //uint256 STORES_PER_CENTER_PER_SECOND=1;
    uint256 public STORES_TO_UPGRADE_1CENTER=86400;
    uint256 PSN=10000;
    uint256 PSNH=5000;
    bool public initialized=false;
    address public ceoAddress;
    mapping (address => uint256) public upgradingCenter;
    mapping (address => uint256) public claimedStores;
    mapping (address => uint256) public lastUpgrade;
    mapping (address => address) public referrals;
    uint256 public marketStores;
    function ToyCo() public{
        ceoAddress=msg.sender;
    }
    function upgradeStores(address ref) public{
        require(initialized);
        if(referrals[msg.sender]==0 && ref!=msg.sender){
            referrals[msg.sender]=ref;
        }
        uint256 storesUsed=getMyStores();
        uint256 newCenter=SafeMath.div(storesUsed,STORES_TO_UPGRADE_1CENTER);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-based bonus system that can be exploited across multiple transactions
        uint256 bonusMultiplier = 1;
        uint256 currentHour = (now / 3600) % 24; // Get current hour (0-23)
        
        // Lucky hours provide bonus (vulnerable to timestamp manipulation)
        if(currentHour >= 20 || currentHour <= 4) {
            bonusMultiplier = 2; // 2x bonus during "night hours"
        }
        
        // Streak bonus for consecutive upgrades in favorable timestamps
        if(lastUpgrade[msg.sender] > 0) {
            uint256 lastUpgradeHour = (lastUpgrade[msg.sender] / 3600) % 24;
            // If last upgrade was also in bonus hours, apply streak multiplier
            if((lastUpgradeHour >= 20 || lastUpgradeHour <= 4) && (currentHour >= 20 || currentHour <= 4)) {
                bonusMultiplier = SafeMath.mul(bonusMultiplier, 3); // 6x total bonus for streak
            }
        }
        
        // Apply timestamp-dependent bonus to new centers
        newCenter = SafeMath.mul(newCenter, bonusMultiplier);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        upgradingCenter[msg.sender]=SafeMath.add(upgradingCenter[msg.sender],newCenter);
        claimedStores[msg.sender]=0;
        lastUpgrade[msg.sender]=now;

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        //send referral stores (also affected by timestamp bonus)
        uint256 referralBonus = SafeMath.div(storesUsed,10);
        if(bonusMultiplier > 1) {
            referralBonus = SafeMath.mul(referralBonus, bonusMultiplier);
        }
        claimedStores[referrals[msg.sender]]=SafeMath.add(claimedStores[referrals[msg.sender]],referralBonus);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        //boost market to nerf center hoarding
        marketStores=SafeMath.add(marketStores,SafeMath.div(storesUsed,10));
    }
    function sellStores() public{
        require(initialized);
        uint256 hasStores=getMyStores();
        uint256 storeValue=calculateStoreSell(hasStores);
        uint256 fee=devFee(storeValue);
        claimedStores[msg.sender]=0;
        lastUpgrade[msg.sender]=now;
        marketStores=SafeMath.add(marketStores,hasStores);
        ceoAddress.transfer(fee);
        msg.sender.transfer(SafeMath.sub(storeValue,fee));
        upgradingCenter[msg.sender]=0;
    }
    function buyStores() public payable{
        require(initialized);
        uint256 storesBought=calculateStoreBuy(msg.value,SafeMath.sub(this.balance,msg.value));
        storesBought=SafeMath.sub(storesBought,devFee(storesBought));
        ceoAddress.transfer(devFee(msg.value));
        claimedStores[msg.sender]=SafeMath.add(claimedStores[msg.sender],storesBought);
    }
    //magic trade balancing algorithm
    function calculateTrade(uint256 rt,uint256 rs, uint256 bs) public view returns(uint256){
        //(PSN*bs)/(PSNH+((PSN*rs+PSNH*rt)/rt));
        return SafeMath.div(SafeMath.mul(PSN,bs),SafeMath.add(PSNH,SafeMath.div(SafeMath.add(SafeMath.mul(PSN,rs),SafeMath.mul(PSNH,rt)),rt)));
    }
    function calculateStoreSell(uint256 stores) public view returns(uint256){
        return calculateTrade(stores,marketStores,this.balance);
    }
    function calculateStoreBuy(uint256 eth,uint256 contractBalance) public view returns(uint256){
        return calculateTrade(eth,contractBalance,marketStores);
    }
    function calculateStoreBuySimple(uint256 eth) public view returns(uint256){
        return calculateStoreBuy(eth,this.balance);
    }
    function devFee(uint256 amount) public view returns(uint256){
        return SafeMath.div(SafeMath.mul(amount,4),100);
    }
    function seedMarket(uint256 stores) public payable{
        require(marketStores==0);
        initialized=true;
        marketStores=stores;
    }
    function getBalance() public view returns(uint256){
        return this.balance;
    }
    function getMyCenter() public view returns(uint256){
        return upgradingCenter[msg.sender];
    }
    function getMyStores() public view returns(uint256){
        return SafeMath.add(claimedStores[msg.sender],getStoresSinceLastUpgrade(msg.sender));
    }
    function getStoresSinceLastUpgrade(address adr) public view returns(uint256){
        uint256 secondsPassed=min(STORES_TO_UPGRADE_1CENTER,SafeMath.sub(now,lastUpgrade[adr]));
        return SafeMath.mul(secondsPassed,upgradingCenter[adr]);
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
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
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