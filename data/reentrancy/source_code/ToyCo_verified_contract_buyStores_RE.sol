/*
 * ===== SmartInject Injection Details =====
 * Function      : buyStores
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State**: Created a `pendingPurchases` mapping that tracks accumulated purchase amounts across transactions
 * 2. **External Callback**: Added an external call to `msg.sender` with `onStoresPurchased` callback before state finalization
 * 3. **State Accumulation**: The callback can manipulate `pendingPurchases` state which persists between transactions
 * 4. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Initial `buyStores()` call sets `pendingPurchases[attacker] = X`
 *    - Transaction 2: In callback, attacker calls `buyStores()` again, setting `pendingPurchases[attacker] = X + Y`
 *    - Transaction 3: When original call completes, it adds entire accumulated `pendingPurchases` to `claimedStores`
 *    - Result: Attacker gets stores for multiple purchases but only pays for one
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction establishes the pending state
 * - Subsequent transactions in the callback accumulate more pending purchases
 * - Final state update uses the accumulated amount
 * - Single transaction cannot exploit this due to the stateful accumulation requirement
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
    mapping (address => uint256) public pendingPurchases; // Added declaration
    uint256 public marketStores;
    constructor() public{
        ceoAddress=msg.sender;
    }
    function upgradeStores(address ref) public{
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending purchase state before external call
        pendingPurchases[msg.sender] = SafeMath.add(pendingPurchases[msg.sender], storesBought);
        
        // External call to user-controlled contract for purchase notification
        if(msg.sender != ceoAddress && msg.sender.call.value(0)(bytes4(keccak256("onStoresPurchased(uint256)")), storesBought)) {
            // If callback succeeds, finalize the purchase
            claimedStores[msg.sender]=SafeMath.add(claimedStores[msg.sender],pendingPurchases[msg.sender]);
            pendingPurchases[msg.sender] = 0;
        } else {
            // If callback fails, still finalize purchase but with original amount
            claimedStores[msg.sender]=SafeMath.add(claimedStores[msg.sender],storesBought);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        ceoAddress.transfer(devFee(msg.value));
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
