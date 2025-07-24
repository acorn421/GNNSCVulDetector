/*
 * ===== SmartInject Injection Details =====
 * Function      : sellStores
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending Withdrawal State**: Introduced `pendingWithdrawals[msg.sender]` tracking that persists between transactions, creating stateful vulnerability surface.
 * 
 * 2. **Moved State Updates After External Call**: Critical state modifications (claimedStores, lastUpgrade, marketStores, upgradingCenter) now occur AFTER the external call to user's address, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Used Low-Level Call**: Replaced `transfer()` with `call.value()` which provides more gas to the recipient and enables complex callback execution during reentrancy.
 * 
 * 4. **Conditional State Updates**: State is only updated if the external call succeeds, creating a window where partial state exists between transactions.
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls `sellStores()` - `pendingWithdrawals` is set, external call triggers attacker's fallback
 * - **During Callback**: Attacker's fallback re-enters `sellStores()` - sees stale state (non-zero stores) but has pending withdrawal
 * - **Transaction 2**: Subsequent calls can exploit inconsistent state where withdrawals are pending but stores haven't been reset
 * - **State Accumulation**: Multiple re-entries accumulate withdrawal amounts while stores remain available for calculation
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the `pendingWithdrawals` state to be established in one transaction
 * - Exploitation depends on the persistent state from previous calls
 * - The callback mechanism enables state manipulation across transaction boundaries
 * - Single-transaction exploitation is limited by gas constraints and state dependencies
 * 
 * This creates a realistic vulnerability where the contract maintains inconsistent state across multiple transactions, enabling attackers to drain funds through accumulated reentrancy attacks.
 */
pragma solidity ^0.4.18; // solhint-disable-line



contract ToyCo {
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
    // Added mapping for pendingWithdrawals to fix undeclared identifier errors
    mapping(address => uint256) public pendingWithdrawals;
    constructor() public {
        ceoAddress=msg.sender;
    }
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending withdrawal tracking for multi-transaction vulnerability
        if(pendingWithdrawals[msg.sender] == 0) {
            pendingWithdrawals[msg.sender] = SafeMath.sub(storeValue,fee);
        }
        
        // External call before state update - enables reentrancy
        ceoAddress.transfer(fee);
        
        // User withdrawal with callback opportunity
        if(msg.sender.call.value(pendingWithdrawals[msg.sender])("") ) {
            // State updates happen AFTER external call - vulnerable to reentrancy
            claimedStores[msg.sender]=0;
            lastUpgrade[msg.sender]=now;
            marketStores=SafeMath.add(marketStores,hasStores);
            upgradingCenter[msg.sender]=0;
            pendingWithdrawals[msg.sender]=0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
