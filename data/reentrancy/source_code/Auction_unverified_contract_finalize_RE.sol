/*
 * ===== SmartInject Injection Details =====
 * Function      : finalize
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering operations to place external calls before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. **Moved `finalized = true` to the END**: Now set after all external calls instead of first
 * 2. **Separated external calls from state cleanup**: External calls to bidders happen in first loop, state cleanup in second loop
 * 3. **Maintained bid values during external calls**: `bids[accountsList[i]]` remains non-zero during external calls, enabling reentrancy
 * 4. **Preserved beneficiary payment order**: Still happens early but now before any state protection
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * - **Transaction 1**: Owner calls `finalize()` → External call to malicious bidder contract
 * - **Transaction 2**: Malicious bidder's fallback function re-enters `finalize()` (finalized still false)
 * - **Transaction 3**: Second re-entry continues, potentially calling other functions like `refund()`
 * - **State Accumulation**: Each re-entry can manipulate the auction state before `finalized` is set
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * 1. **Stateful Protection**: The `finalized` flag persists across transactions and prevents re-execution
 * 2. **State Dependency**: Exploit requires `finalized` to remain false during external calls
 * 3. **Cross-Function Reentrancy**: Malicious contracts can call other functions during re-entry
 * 4. **Persistent State Changes**: Bid amounts and winner state persist between transactions, enabling complex attack sequences
 * 
 * **REALISTIC EXPLOITATION:**
 * A malicious bidder can deploy a contract that, when receiving refunds, re-enters the auction to manipulate the winner, drain additional funds, or exploit other state-dependent functions before the auction is properly finalized.
 */
pragma solidity ^0.4.23;

// Deploying version: https://github.com/astralship/auction-ethereum/commit/1359e14e0319c6019eb9c7e57348b95c722e3dd6
// Timestamp Converter: 1529279999
// Is equivalent to: 06/17/2018 @ 11:59pm (UTC)
// Sunday midnight, in a week 😎

contract Auction {
  
  string public description;
  string public instructions; // will be used for delivery address or email
  uint public price;
  bool public initialPrice = true; // at first asking price is OK, then +25% required
  uint public timestampEnd;
  address public beneficiary;
  bool public finalized = false;

  address public owner;
  address public winner;
  mapping(address => uint) public bids;
  address[] public accountsList; // so we can iterate: https://ethereum.stackexchange.com/questions/13167/are-there-well-solved-and-simple-storage-patterns-for-solidity

  // THINK: should be (an optional) constructor parameter?
  // For now if you want to change - simply modify the code
  uint public increaseTimeIfBidBeforeEnd = 24 * 60 * 60; // Naming things: https://www.instagram.com/p/BSa_O5zjh8X/
  uint public increaseTimeBy = 24 * 60 * 60;
  

  event Bid(address indexed winner, uint indexed price, uint indexed timestamp);
  event Refund(address indexed sender, uint indexed amount, uint indexed timestamp);
  
  modifier onlyOwner { require(owner == msg.sender, "only owner"); _; }
  modifier onlyWinner { require(winner == msg.sender, "only winner"); _; }
  modifier ended { require(now > timestampEnd, "not ended yet"); _; }

  function setDescription(string _description) public onlyOwner() {
    description = _description;
  }

  function setInstructions(string _instructions) public ended() onlyWinner()  {
    instructions = _instructions;
  }

  constructor(uint _price, string _description, uint _timestampEnd, address _beneficiary) public {
    require(_timestampEnd > now, "end of the auction must be in the future");
    owner = msg.sender;
    price = _price;
    description = _description;
    timestampEnd = _timestampEnd;
    beneficiary = _beneficiary;
  }

  function() public payable {

    if (msg.value == 0) { // when sending `0` it acts as if it was `withdraw`
      refund();
      return;
    }

    require(now < timestampEnd, "auction has ended"); // sending ether only allowed before the end

    if (bids[msg.sender] > 0) { // First we add the bid to an existing bid
      bids[msg.sender] += msg.value;
    } else {
      bids[msg.sender] = msg.value;
      accountsList.push(msg.sender); // this is out first bid, therefore adding 
    }

    if (initialPrice) {
      require(bids[msg.sender] >= price, "bid too low, minimum is the initial price");
    } else {
      require(bids[msg.sender] >= (price * 5 / 4), "bid too low, minimum 25% increment");
    }
    
    if (now > timestampEnd - increaseTimeIfBidBeforeEnd) {
      timestampEnd = now + increaseTimeBy;
    }

    initialPrice = false;
    price = bids[msg.sender];
    winner = msg.sender;
    emit Bid(winner, price, now);
  }

  function finalize() public ended() onlyOwner() {
    require(finalized == false, "can withdraw only once");
    require(initialPrice == false, "can withdraw only if there were bids");

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Pay beneficiary first - external call before state changes
    beneficiary.send(price);
    
    // Start refund process - external calls to bidders before clearing their bids
    for (uint i = 0; i < accountsList.length;  i++) {
      if (bids[accountsList[i]] > 0 && accountsList[i] != winner) {
        accountsList[i].send( bids[accountsList[i]] ); // External call to potentially malicious contract
        // Note: bids[accountsList[i]] is cleared AFTER the external call
      }
    }
    
    // State cleanup happens after external calls - vulnerable to reentrancy
    bids[winner] = 0; // Clear winner's bid
    for (uint j = 0; j < accountsList.length; j++) {
      if (accountsList[j] != winner) {
        bids[accountsList[j]] = 0; // Clear losing bids
      }
    }
    
    finalized = true; // Critical: finalized flag set LAST, after all external calls
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
  function refund() public {
    require(msg.sender != winner, "winner cannot refund");

    msg.sender.send( bids[msg.sender] );
    emit Refund(msg.sender, bids[msg.sender], now);
    bids[msg.sender] = 0;
  }

}
