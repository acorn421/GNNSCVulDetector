/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptMembership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the account address after balance updates but before event emission. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that can receive the onMembershipActivated callback
 * **Transaction 2 (Exploit)**: When acceptMembership is called, the external callback allows the attacker to:
 * - Re-enter the contract while balances are already updated
 * - Call other functions like withdraw() or deposit() to manipulate state
 * - Potentially call acceptMembership again if they have accumulated sufficient balance
 * 
 * **Multi-Transaction Exploitation Path**:
 * 1. **State Accumulation Phase**: Attacker builds up balance through multiple deposit transactions
 * 2. **Activation Phase**: Bot calls acceptMembership, triggering the callback after balance updates
 * 3. **Exploitation Phase**: During callback, attacker re-enters to manipulate balances or withdraw funds
 * 4. **Completion Phase**: Original transaction completes, but state is now inconsistent
 * 
 * **Why Multi-Transaction**:
 * - Requires prior balance accumulation across multiple deposits
 * - State changes persist between the setup and exploitation phases  
 * - The callback happens after state updates, creating a window for cross-transaction exploitation
 * - Cannot be exploited in a single atomic transaction due to the need for pre-existing balance state
 * 
 * The external call creates a classic reentrancy vulnerability where the contract state is partially updated, allowing attackers to exploit the inconsistent state through callbacks that can trigger additional state changes.
 */
pragma solidity ^0.4.17;

/*

Signals Society Membership Contract
-----------------------------------

*/

/**
 * Ownership functionality
 */
contract Ownable {
  address public owner;
  address public bot;
  // constructor, sets original owner address
  constructor() public {
    owner = msg.sender;
  }
  // modifier to restruct function use to the owner
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }    
  // modifier to restruct function use to the bot
  modifier onlyBot() {
    require(msg.sender == bot);
    _;
  }
  // lets owner change his address
  function changeOwner(address addr) public onlyOwner {
      owner = addr;
  }
  // lets owner change the bot's address    
  function changeBot(address addr) public onlyOwner {
      bot = addr;
  }
  // allows destruction of contract only if balance is empty
  function kill() public onlyOwner {
    require(address(this).balance == 0);
    selfdestruct(owner);
  }
}

/**
 * Manages membership prices
 */
contract Memberships is Ownable {
  // enumerates memberships (0, 1, 2)
  enum Membership { Day, Month, Lifetime }
  // holds the prices for the memberships
  mapping (uint => uint) internal prices;
  // returns the price for a single membership
  function getMembershipPrice(Membership membership) public view returns(uint) {
    return prices[uint(membership)];
  }
  // lets the owner set the price for a single membership
  function setMembershipPrice(Membership membership, uint amount) public onlyOwner {    
    require(amount > 0);
    prices[uint(membership)] = amount;
  }
}

/**
 * SignalsSociety Contract
 */
contract SignalsSociety is Ownable, Memberships {
  // lets the bot know a deposit was made
  event Deposited(address account, uint amount, uint balance, uint timestamp);
  // lets the bot know a membership was paid
  event MembershipPaid(address account, Membership membership, uint timestamp);

  // store the amount of ETH deposited by each account.
  mapping (address => uint) public balances;

  // allows user to withdraw his balance
  function withdraw() public {
    uint amount = balances[msg.sender];
    // zero the pending refund before sending to prevent re-entrancy attacks
    balances[msg.sender] = 0;
    msg.sender.transfer(amount);
  }
  // deposits ETH to a user's account
  function deposit(address account, uint amount) public {
    // deposit the amount to the user's account
    balances[account] += amount;
    // let the bot know something was deposited
    emit Deposited(account, amount, balances[account], now);
  }
  // accepts the membership payment by moving eth from the user's account
  // to the owner's account
  function acceptMembership(address account, Membership membership, uint discount) public onlyBot {
    // get the price for the membership they selected minus any discounts for special promotions
    uint price = getMembershipPrice(membership) - discount;
    // make sure they have enough balance to pay for it
    require(balances[account] >= price);
    // transfer the price to the contract owner account
    balances[account] -= price;
    balances[owner] += price;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // notify the account holder about membership activation via callback
    // this enables membership-specific features on their contract
    uint size;
    assembly { size := extcodesize(account) }
    if (size > 0) {
        bool success;
        bytes memory data = abi.encodeWithSignature("onMembershipActivated(uint8,uint256)", uint8(membership), price);
        assembly {
            let ptr := add(data, 32)
            success := call(gas, account, 0, ptr, mload(data), 0, 0)
        }
        require(success, "Membership activation callback failed");
    }
    // let the bot know the membership was paid
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit MembershipPaid(account, membership, now);
  }
  // default function.  Called when a user sends ETH to the contract.
  // deposits the eth to their bank account
  function () public payable {
    deposit(msg.sender, msg.value);
  }
}
