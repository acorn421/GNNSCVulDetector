/*
 * ===== SmartInject Injection Details =====
 * Function      : upgradeStores
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the referrer before completing state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `referrals[msg.sender]` using low-level `call()` method
 * 2. The external call occurs before critical state updates (violating Checks-Effects-Interactions pattern)
 * 3. Moved referral store allocation after the external call, creating a reentrancy window
 * 4. The external call passes sensitive state information (referralStores, newCenter) to the referrer
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker sets up a malicious referrer contract and calls `upgradeStores()` to establish initial state
 * 2. **Transaction 2**: Attacker accumulates stores over time and calls `upgradeStores()` again
 * 3. **During Transaction 2**: The malicious referrer contract receives the callback and re-enters `upgradeStores()` before state updates complete
 * 4. **Exploitation**: The re-entrant call sees stale state (old `claimedStores`, `lastUpgrade`) allowing the attacker to:
 *    - Double-spend their stores across multiple upgrade cycles
 *    - Manipulate the time-based calculations by exploiting the unchanged `lastUpgrade` timestamp
 *    - Accumulate excessive `upgradingCenter` values through repeated re-entrancy
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **Time-Based Accumulation**: The vulnerability depends on accumulated stores over time via `getMyStores()` which uses `lastUpgrade` timestamps
 * 2. **State Persistence**: The attacker needs to build up legitimate `upgradingCenter` values across multiple transactions to maximize exploitation
 * 3. **Referral Relationship**: The first transaction must establish the referral relationship, then subsequent transactions can exploit it
 * 4. **Realistic Attack Window**: The vulnerability becomes more profitable as the attacker accumulates more stores over multiple upgrade cycles
 * 
 * This creates a realistic vulnerability where the attacker must plan across multiple transactions, making it a genuine stateful, multi-transaction reentrancy vulnerability.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint256 referralStores=SafeMath.div(storesUsed,10);
        
        // Notify referrer about the upgrade and transfer referral stores
        if(referrals[msg.sender] != 0) {
            // External call to referrer before state updates - vulnerable to reentrancy
            bool success = referrals[msg.sender].call(bytes4(keccak256("onReferralUpgrade(address,uint256,uint256)")), msg.sender, referralStores, newCenter);
            // State updates happen after external call - violates CEI pattern
            claimedStores[referrals[msg.sender]]=SafeMath.add(claimedStores[referrals[msg.sender]],referralStores);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        upgradingCenter[msg.sender]=SafeMath.add(upgradingCenter[msg.sender],newCenter);
        claimedStores[msg.sender]=0;
        lastUpgrade[msg.sender]=now;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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