/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduledUpgrade
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a multi-transaction timestamp dependence vulnerability. Users can schedule upgrades with time delays and receive bonus centers for executing them later. The vulnerability requires: 1) First transaction to schedule the upgrade, 2) Second transaction to execute it after the timestamp condition is met. Miners can manipulate block timestamps to either prevent execution or gain additional time bonuses, making the vulnerability stateful and requiring multiple transactions to exploit.
 */
pragma solidity ^0.4.18; // solhint-disable-line

contract ToyCo {
    // uint256 STORES_PER_CENTER_PER_SECOND=1;
    uint256 public STORES_TO_UPGRADE_1CENTER = 86400;
    uint256 PSN = 10000;
    uint256 PSNH = 5000;
    bool public initialized = false;
    address public ceoAddress;
    mapping (address => uint256) public upgradingCenter;
    mapping (address => uint256) public claimedStores;
    mapping (address => uint256) public lastUpgrade;
    mapping (address => address) public referrals;
    uint256 public marketStores;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) scheduledUpgradeTime;
    mapping (address => uint256) scheduledUpgradeAmount;
    
    function ToyCo() public {
        ceoAddress = msg.sender;
    }

    function scheduleUpgrade(uint256 delaySeconds) public {
        require(initialized);
        require(delaySeconds >= 60); // At least 1 minute delay
        require(scheduledUpgradeTime[msg.sender] == 0); // No existing scheduled upgrade
        
        uint256 storesUsed = getMyStores();
        require(storesUsed > 0);
        
        scheduledUpgradeTime[msg.sender] = now + delaySeconds;
        scheduledUpgradeAmount[msg.sender] = storesUsed;
        
        // Lock the stores by setting claimed stores to 0
        claimedStores[msg.sender] = 0;
        lastUpgrade[msg.sender] = now;
    }
    
    function executeScheduledUpgrade() public {
        require(initialized);
        require(scheduledUpgradeTime[msg.sender] != 0);
        require(now >= scheduledUpgradeTime[msg.sender]); // Vulnerable to timestamp manipulation
        
        uint256 storesUsed = scheduledUpgradeAmount[msg.sender];
        uint256 newCenter = SafeMath.div(storesUsed, STORES_TO_UPGRADE_1CENTER);
        
        // Bonus centers for waiting (creates incentive for manipulation)
        uint256 timeBonus = SafeMath.div(SafeMath.sub(now, scheduledUpgradeTime[msg.sender]), 3600); // 1 bonus per hour late
        newCenter = SafeMath.add(newCenter, timeBonus);
        
        upgradingCenter[msg.sender] = SafeMath.add(upgradingCenter[msg.sender], newCenter);
        
        // Clear scheduled upgrade
        scheduledUpgradeTime[msg.sender] = 0;
        scheduledUpgradeAmount[msg.sender] = 0;
        
        // Boost market
        marketStores = SafeMath.add(marketStores, SafeMath.div(storesUsed, 10));
    }
    // === END FALLBACK INJECTION ===

    function upgradeStores(address ref) public {
        require(initialized);
        if(referrals[msg.sender]==0 && ref!=msg.sender){
            referrals[msg.sender]=ref;
        }
        uint256 storesUsed=getMyStores();
        uint256 newCenter=SafeMath.div(storesUsed,STORES_TO_UPGRADE_1CENTER);
        upgradingCenter[msg.sender]=SafeMath.add(upgradingCenter[msg.sender],newCenter);
        claimedStores[msg.sender]=0;
        lastUpgrade[msg.sender]=now;

        //send referral stores
        claimedStores[referrals[msg.sender]]=SafeMath.add(claimedStores[referrals[msg.sender]],SafeMath.div(storesUsed,10));

        //boost market to nerf center hoarding
        marketStores=SafeMath.add(marketStores,SafeMath.div(storesUsed,10));
    }
    function sellStores() public {
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
    function buyStores() public payable {
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
    function seedMarket(uint256 stores) public payable {
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
