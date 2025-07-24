/*
 * ===== SmartInject Injection Details =====
 * Function      : hireBountyHunter
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added callback mechanism**: Introduced a call to `onBountyTransfer()` callback on user contracts, creating a reentrancy vector that persists across transactions.
 * 
 * 2. **Preserved original user reference**: Stored `originalUser` before price calculations to enable multi-transaction exploitation where the callback can manipulate future state.
 * 
 * 3. **Moved critical state updates after external calls**: The `data[bountyHunterID].user` and `data[bountyHunterID].last_transaction` updates now occur AFTER the external calls, violating the Checks-Effects-Interactions pattern.
 * 
 * 4. **Multi-transaction exploitation path**:
 *    - **Transaction 1**: Attacker calls `hireBountyHunter()`, receives callback during `payoutOnPurchase()` or `onBountyTransfer()`, can reenter with different parameters
 *    - **Transaction 2**: Attacker exploits inconsistent state where `originalUser` still references old owner but price has been updated
 *    - **Transaction 3+**: Attacker continues exploitation based on accumulated state changes and callback manipulation
 * 
 * 5. **Stateful dependency**: The vulnerability requires multiple transactions because:
 *    - The callback mechanism builds up state across calls
 *    - The `last_transaction` timestamp creates time-based dependencies
 *    - The attacker needs to accumulate state changes through multiple reentrancy calls to maximize exploitation
 * 
 * The vulnerability is realistic as it mimics real-world patterns where contracts implement callback mechanisms for user notification, but fail to properly guard against reentrancy in multi-transaction scenarios.
 */
pragma solidity ^0.4.19;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
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


contract BountyHunter {

  function() public payable { }

  string public constant NAME = "BountyHunter";
  string public constant SYMBOL = "BountyHunter";
  address ceoAddress = 0xc10A6AedE9564efcDC5E842772313f0669D79497;
  address hunter;
  address hunted;

  struct ContractData {
    address user;
    uint256 hunterPrice;
    uint256 last_transaction;
   
  }

  ContractData[8] data;
  

  // Changed to 'constructor' as per Solidity 0.4.19+ best practices
  constructor() public {
    for (uint i = 0; i < 8; i++) {
     
      data[i].hunterPrice = 5000000000000000;
      data[i].user = msg.sender;
      data[i].last_transaction = block.timestamp;
    }
  }


  function payoutOnPurchase(address previousHunterOwner, uint256 hunterPrice) private {
    previousHunterOwner.transfer(hunterPrice);
  }
  function transactionFee(address, uint256 hunterPrice) private {
    ceoAddress.transfer(hunterPrice);
  }
  function createBounty(uint256 hunterPrice) private {
    address(this).transfer(hunterPrice);
  }


  
  function hireBountyHunter(uint bountyHunterID) public payable returns (uint, uint) {
    require(bountyHunterID >= 0 && bountyHunterID <= 8);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Store original user before price calculation for multi-transaction reentrancy
    address originalUser = data[bountyHunterID].user;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    if ( data[bountyHunterID].hunterPrice == 5000000000000000 ) {
      data[bountyHunterID].hunterPrice = 10000000000000000;
    }
    else { 
      data[bountyHunterID].hunterPrice = data[bountyHunterID].hunterPrice * 2;
    }
    
    require(msg.value >= data[bountyHunterID].hunterPrice * uint256(1));

    createBounty((data[bountyHunterID].hunterPrice / 10) * (3));
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // VULNERABILITY: External call to potentially malicious contract BEFORE state update
    // This allows reentrancy that can manipulate state across multiple transactions
    payoutOnPurchase(originalUser, (data[bountyHunterID].hunterPrice / 10) * (6));
    
    // VULNERABILITY: Additional external call that can trigger callback during reentrancy
    // FIX: Use extcodesize (see changes)
    uint size;
    assembly { size := extcodesize(originalUser) }
    if (originalUser != ceoAddress && size > 0) {
        require(originalUser.call(bytes4(keccak256("onBountyTransfer(uint256,uint256)")), bountyHunterID, data[bountyHunterID].hunterPrice));
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    transactionFee(ceoAddress, (data[bountyHunterID].hunterPrice / 10) * (1));

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // VULNERABILITY: Critical state update happens AFTER external calls
    // This allows reentrancy to exploit inconsistent state across transactions
    data[bountyHunterID].user = msg.sender;
    data[bountyHunterID].last_transaction = block.timestamp;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    playerKiller();
    
    return (bountyHunterID, data[bountyHunterID].hunterPrice);

  }


  function getUsers() public view returns (address[], uint256[]) {
    address[] memory users = new address[](8);
    uint256[] memory hunterPrices =  new uint256[](8);
    for (uint i=0; i<8; i++) {
      if (data[i].user != ceoAddress){
        users[i] = (data[i].user);
      }
      else{
        users[i] = address(0);
      }
      
      hunterPrices[i] = (data[i].hunterPrice);
    }
    return (users,hunterPrices);
  }

  function rand(uint max) public returns (uint256){
        
    uint256 lastBlockNumber = block.number - 1;
    uint256 hashVal = uint256(block.blockhash(lastBlockNumber));

    uint256 FACTOR = 1157920892373161954235709850086879078532699846656405640394575840079131296399;
    return uint256(uint256( (hashVal) / FACTOR) + 1) % max;
  }
  
  
  function playerKiller() private {
    uint256 killshot = rand(31);

    if( (killshot < 8) &&  (msg.sender != data[killshot].user) ){
      hunter = msg.sender;
      if( ceoAddress != data[killshot].user){
        hunted = data[killshot].user;
      }
      else{
        hunted = address(0);
      }
      
      data[killshot].hunterPrice  = 5000000000000000;
      data[killshot].user  = 5000000000000000;

      msg.sender.transfer((this.balance / 10) * (9));
      ceoAddress.transfer((this.balance / 10) * (1));

    }
    
  }

  function killFeed() public view returns(address, address){
    return(hunter, hunted);
  }
  
}
