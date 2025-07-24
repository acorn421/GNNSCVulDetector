/*
 * ===== SmartInject Injection Details =====
 * Function      : hireBountyHunter
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a time-based pricing mechanism that creates cumulative discounts for rapid successive purchases. The vulnerability allows attackers to exploit block timestamp manipulation and miner influence to obtain significant discounts by controlling the timing of multiple transactions. The attack requires building up state through multiple transactions to maximize the discount benefits, making it a stateful multi-transaction vulnerability.
 * 
 * **Specific Changes Made:**
 * 1. **Added time-based discount calculation** using `block.timestamp - data[bountyHunterID].last_transaction`
 * 2. **Implemented cumulative discount logic** that rewards rapid successive purchases with up to 30% discounts
 * 3. **Updated state with new timestamp** after each purchase to maintain timing state for future transactions
 * 4. **Applied discount to all financial calculations** including payouts and fees
 * 
 * **Multi-Transaction Exploitation Vector:**
 * 1. **Transaction 1**: Attacker purchases a bounty hunter, establishing a `last_transaction` timestamp
 * 2. **Transaction 2**: Attacker (or collaborating miner) manipulates block timestamp to appear within discount window and purchases again at reduced price
 * 3. **Transaction 3+**: Attacker repeats this process across multiple bounty hunters or same hunter (after reset) to accumulate savings
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires establishing a baseline `last_transaction` timestamp in the first transaction
 * - Subsequent transactions build upon this state to calculate time-based discounts
 * - Maximum exploitation requires coordinating multiple purchases across different blocks with controlled timestamps
 * - The attack cannot be executed in a single transaction as it depends on the time difference between separate blockchain transactions
 * 
 * **Realistic Attack Scenario:**
 * A malicious miner or attacker with influence over block timestamps could coordinate multiple transactions to systematically purchase bounty hunters at significant discounts by manipulating the perceived time elapsed between purchases, potentially saving up to 30% per transaction while the system maintains the appearance of legitimate time-based pricing.
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
  

  
  function BountyHunter() public {
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
    this.transfer(hunterPrice);
  }


  
  function hireBountyHunter(uint bountyHunterID) public payable returns (uint, uint) {
    require(bountyHunterID >= 0 && bountyHunterID <= 8);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based pricing mechanism with cumulative discounts
    uint256 timeSinceLastPurchase = block.timestamp - data[bountyHunterID].last_transaction;
    uint256 discountFactor = 100; // Start with no discount (100%)
    
    // Accumulate discounts for rapid successive purchases (within same block or close blocks)
    if (timeSinceLastPurchase < 60) { // Less than 1 minute
        discountFactor = 70; // 30% discount for quick purchases
    } else if (timeSinceLastPurchase < 300) { // Less than 5 minutes
        discountFactor = 85; // 15% discount
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    
    if ( data[bountyHunterID].hunterPrice == 5000000000000000 ) {
      data[bountyHunterID].hunterPrice = 10000000000000000;
    }
    else { 
      data[bountyHunterID].hunterPrice = data[bountyHunterID].hunterPrice * 2;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Apply time-based discount to final price
    uint256 finalPrice = (data[bountyHunterID].hunterPrice * discountFactor) / 100;
    
    require(msg.value >= finalPrice * uint256(1));

    createBounty((finalPrice / 10) * (3));
    
    payoutOnPurchase(data[bountyHunterID].user,  (finalPrice / 10) * (6));
    
    transactionFee(ceoAddress, (finalPrice / 10) * (1));
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    
    data[bountyHunterID].user = msg.sender;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Update timestamp for next purchase calculation
    data[bountyHunterID].last_transaction = block.timestamp;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    playerKiller();
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    return (bountyHunterID, finalPrice);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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