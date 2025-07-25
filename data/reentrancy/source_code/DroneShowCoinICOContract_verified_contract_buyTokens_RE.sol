/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Created a `pendingPurchases` mapping to track user purchases across transactions, making the vulnerability stateful and persistent.
 * 
 * 2. **Conditional Vulnerable Path**: After 5 transactions (tracked by `numberOfTransactions`), the function enters a vulnerable execution path where:
 *    - External token transfer happens BEFORE state updates
 *    - State variables (raisedAmount, bonusesGiven, numberOfTransactions) are updated AFTER the external call
 *    - This violates the Checks-Effects-Interactions pattern
 * 
 * 3. **Multi-Transaction Requirement**: The vulnerability requires:
 *    - **Transaction 1-4**: Initial purchases that build up the `numberOfTransactions` counter safely
 *    - **Transaction 5+**: Triggers the vulnerable path where reentrancy becomes possible
 * 
 * 4. **Exploitation Scenario**: 
 *    - Attacker makes 4 legitimate purchases to reach the threshold
 *    - On the 5th purchase, the attacker's malicious token contract can re-enter `buyTokens()` 
 *    - During reentrancy, state variables haven't been updated yet, allowing multiple token transfers
 *    - Each reentrant call can claim tokens before the state is properly updated
 * 
 * 5. **Realistic Integration**: The vulnerability is disguised as a "VIP user optimization" where frequent buyers get immediate token delivery, making it appear like a legitimate feature rather than a security flaw.
 * 
 * This creates a sophisticated vulnerability that requires multiple transactions to set up the attack conditions and can only be exploited once the accumulated state (numberOfTransactions) reaches the threshold.
 */
pragma solidity ^0.4.11;

/**
 * @title SafeMath
    * @dev Math operations with safety checks that throw on error
       */
library SafeMath {
  function mul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function add(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
  
  function div(uint256 a, uint256 b) internal returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }
}

/**
 * @title Ownable
    * @dev The Ownable contract has an owner address, and provides basic authorization control 
       * functions, this simplifies the implementation of "user permissions". 
          */
contract Ownable {
  address public owner;


  /** 
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
        * account.
             */
  constructor() public {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner. 
        */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
        * @param newOwner The address to transfer ownership to. 
             */
  function transferOwnership(address newOwner) public onlyOwner {
    if (newOwner != address(0)) {
      owner = newOwner;
    }
  }
}

/**
 * @title Token
   * @dev interface for interacting with droneshowcoin token
             */
interface  Token {
 function transfer(address _to, uint256 _value) public returns (bool);
 function balanceOf(address _owner) public constant returns(uint256 balance);
}

contract DroneShowCoinICOContract is Ownable {
    
    using SafeMath for uint256;
    
    Token token;
    
    uint256 public constant RATE = 650; //tokens per ether
    uint256 public constant CAP = 15000; //cap in ether
    uint256 public constant START = 1510754400; //GMT: Wednesday, November 15, 2017 2:00:00 PM
    uint256 public constant DAYS = 30; //
    
    bool public initialized = false;
    uint256 public raisedAmount = 0;
    uint256 public bonusesGiven = 0;
    uint256 public numberOfTransactions = 0;
    
    event BoughtTokens(address indexed to, uint256 value);

    // Add struct for PendingPurchase
    struct PendingPurchase {
        uint256 tokens;
        uint256 bonusAmount;
        uint256 timestamp;
        bool claimed;
    }

    // Mapping for pending purchases
    mapping(address => PendingPurchase) public pendingPurchases;
    
    modifier whenSaleIsActive() {
        assert (isActive());
        _;
    }
    
    constructor(address _tokenAddr) public {
        require(_tokenAddr != 0);
        token = Token(_tokenAddr);
    }
    
    function initialize(uint256 numTokens) public onlyOwner {
        require (initialized == false);
        require (tokensAvailable() == numTokens);
        initialized = true;
    }
    
    function isActive() public constant returns (bool) {
        return (
            initialized == true &&  //check if initialized
            now >= START && //check if after start date
            now <= START.add(DAYS * 1 days) && //check if before end date
            goalReached() == false //check if goal was not reached
        ); // if all of the above are true we are active, else we are not
    }
    
    function goalReached() public constant returns (bool) {
        return (raisedAmount >= CAP * 1 ether);
    }
    
    function () public payable {
        buyTokens();
    }
    
    function buyTokens() public payable whenSaleIsActive {
        uint256 weiAmount = msg.value;
        uint256 tokens = weiAmount.mul(RATE);
        
        uint256 secondspassed = now - START;
        uint256 dayspassed = secondspassed/(60*60*24);
        uint256 bonusPrcnt = 0;
        if (dayspassed < 7) {
            //first 7 days 20% bonus
            bonusPrcnt = 20;
        } else if (dayspassed < 14) {
            //second week 10% bonus
            bonusPrcnt = 10;
        } else {
            //no bonus
            bonusPrcnt = 0;
        }
        uint256 bonusAmount = (tokens * bonusPrcnt) / 100;
        tokens = tokens.add(bonusAmount);
        BoughtTokens(msg.sender, tokens);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store purchase details for potential bonus claim
        pendingPurchases[msg.sender] = PendingPurchase({
            tokens: tokens,
            bonusAmount: bonusAmount,
            timestamp: now,
            claimed: false
        });
        
        // If user has accumulated enough transactions, allow immediate token delivery
        if (numberOfTransactions >= 5) {
            // Vulnerable: External call before state update
            token.transfer(msg.sender, tokens);
            
            // State updates happen after external call - vulnerable to reentrancy
            raisedAmount = raisedAmount.add(msg.value);
            bonusesGiven = bonusesGiven.add(bonusAmount);
            numberOfTransactions = numberOfTransactions.add(1);
            
            // Mark purchase as claimed
            pendingPurchases[msg.sender].claimed = true;
        } else {
            // For new users, update state first (safer pattern)
            raisedAmount = raisedAmount.add(msg.value);
            bonusesGiven = bonusesGiven.add(bonusAmount);
            numberOfTransactions = numberOfTransactions.add(1);
            
            // Tokens will be delivered through separate claimTokens() call
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        owner.transfer(msg.value);
        
    }
    
    function tokensAvailable() public constant returns (uint256) {
        return token.balanceOf(this);
    }
    
    function destroy() public onlyOwner {
        uint256 balance = token.balanceOf(this);
        assert (balance > 0);
        token.transfer(owner,balance);
        selfdestruct(owner);
        
    }
}