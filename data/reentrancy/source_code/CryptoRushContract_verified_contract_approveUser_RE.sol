/*
 * ===== SmartInject Injection Details =====
 * Function      : approveUser
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Update**: Added an external call to notify the user contract about approval BEFORE the state is fully committed. This creates a reentrancy window where the user is partially approved.
 * 
 * 2. **Check-Effects-Interactions Pattern Violation**: The external call occurs before all state updates are complete, allowing reentrant calls to observe inconsistent state.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls approveUser(maliciousContract)
 *    - **During external call**: maliciousContract's onUserApproved() callback executes
 *    - **Reentrant call**: maliciousContract calls other contract functions (like depositFunds) while in partially approved state
 *    - **Transaction 2+**: Exploit accumulated state inconsistencies or call approveUser again
 * 
 * 4. **Stateful Nature**: The vulnerability relies on the persistent state of user approval status and the registeredAccounts counter. The attack requires multiple transactions to:
 *    - First transaction: Trigger the initial approval with reentrancy
 *    - Subsequent transactions: Exploit the accumulated state changes or inconsistencies
 * 
 * 5. **Realistic Business Logic**: The external call serves a legitimate purpose (user notification system) making the vulnerability subtle and realistic.
 * 
 * **Why Multi-Transaction Required**:
 * - The vulnerability cannot be fully exploited in a single atomic transaction
 * - Requires state accumulation across multiple calls to create exploitable conditions
 * - The reentrant callback sets up state that can be exploited in follow-up transactions
 * - The registeredAccounts counter and approval state persist between transactions, enabling complex attack chains
 */
pragma solidity ^0.4.18;

contract CryptoRushContract
{

  address owner;
  address bot = 0x498f2B8129B153A3499E3812485C40178B6A5C48;
  
  uint fee;
  bool registrationClosed;
  uint registeredAccounts; // index
  uint sharedBalanceID;
  
  struct Balance {
      address user; // user address
      uint lockedBalance; // how much funds are currently in the whole ecosystem
      uint currBalance; // how much funds are currently available (to e.g. withdraw)
      bool isInvestor; // special status in case user is investor
      int investorCredit; // if this is > 0 then fees get deducted from this virtual balance
      // This will be extended in the near future to allow for more diversity in calculations
      
  }
  
  

  
  mapping (address => Balance) balances;
  
 


  event UpdateStatus(string _msg);
  event UserStatus(string _msg, address user, uint amount);



  function CryptoRushContract() public 
  {
    owner = msg.sender;
    fee = 10; // 10% default fee
    
    
   // uint _id = balances.length;
    // add owner to the default balances
    balances[owner].user = msg.sender;
    balances[owner].lockedBalance = 0;
    balances[owner].currBalance = 0;
    balances[owner].isInvestor = true;
    balances[owner].investorCredit = 0; // for now I am paying my own fees for proof of concept
    registeredAccounts += 1;
    
  }

  modifier ifOwner()
  {
    if (msg.sender != owner)
    {
      revert();
    }
    _;
  }
  
  modifier ifBot()
  {
    if (msg.sender != bot)
    {
      revert();
    }
    _;
  }
  
  // restricts access to approved users 
  modifier ifApproved()
  {
    if (msg.sender == balances[msg.sender].user)
    {
        _;
    }
    else
    {
        revert();
    }
  }
  
  
  function closeContract() ifOwner
  {
      selfdestruct(owner);
  }
  
  // placeholder in case I manage to implement an auto-updater for V1
  function updateContract() ifOwner
  {
      
  }
  
  // only owner can approve new User and currently owner can't remove user once registered.
  // Transparency and Trust yaaay!
  function approveUser(address _user) ifOwner
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
{
    // Check if user is already approved to prevent double registration
    if (balances[_user].user == _user) {
        return; // Already approved, nothing to do
    }
    
    // Notify external verification system about new user approval
    // This external call happens BEFORE state is fully updated
    uint length;
    assembly { length := extcodesize(_user) }
    if (length > 0) {
        // Call external contract to notify about user approval
        // This creates a reentrancy window where state is partially updated
        bool success = _user.call(bytes4(keccak256("onUserApproved(address)")), _user);
        // Continue regardless of success to maintain functionality
    }
    
    // Update user state (vulnerable: state update after external call)
    balances[_user].user = _user;
    balances[_user].lockedBalance = 0;
    balances[_user].currBalance = 0;
    balances[_user].isInvestor = false;
    
    // Increment registered accounts counter
    registeredAccounts += 1;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  
  function approveAsInvestor(address _user, int _investorCredit) ifOwner
  {
      balances[_user].user = _user;
      balances[_user].isInvestor = true;
      balances[_user].investorCredit = _investorCredit;
      
  }
  
  
  
  // only allow call from owner of the address asking
  function getCurrBalance() public constant returns (uint _balance)
  {
      if(balances[msg.sender].user == msg.sender)
      {
        return balances[msg.sender].currBalance;    
      }
      else
      {
          revert();
      }
      
  }
  
  // only allow call from owner of the address asking
  function getLockedBalance() public constant returns (uint _balance)
  {
      if(balances[msg.sender].user == msg.sender)
      {
        return balances[msg.sender].lockedBalance;    
      }
      else
      {
          revert();
      }
      
  }
  
  // only allow call from owner of the address asking
  function getInvestorCredit() public constant returns (int _balance)
  {
      if(balances[msg.sender].user == msg.sender)
      {
        return balances[msg.sender].investorCredit;    
      }
      else
      {
          revert();
      }
      
  }
  

  // default deposit function used by Users
  function depositFunds() public payable
  {
     
     // if user is not approved then do not add it to the balances in order to stop overbloating the array thus sabotaging the platform
     if (!(msg.sender == balances[msg.sender].user))
     {
        // user is not approved so add it to the owner's account balance
        
        balances[owner].currBalance += msg.value;
        UserStatus('User is not approved thus donating ether to the contract', msg.sender, msg.value);
     }
     else
     {  // user is approved so add it to their balance
         
        balances[msg.sender].currBalance += msg.value; // and current balance
        UserStatus('User has deposited some funds', msg.sender, msg.value);
     }
      
      
      
  }

 

  function withdrawFunds (uint amount) public ifApproved
  {
      if (balances[msg.sender].currBalance >= amount)
      {
          // user has enough funds, so pay him out!
          
          balances[msg.sender].currBalance -= amount;
         
          
          // this function can be called multiple times so stop that from happening by
          // removing the balances before the transaction is being sent!
          
          if (msg.sender.send(amount)) 
          {
              // all okay!
               UserStatus("User has withdrawn funds", msg.sender, amount);
          }
          else
          {
              // if send failed, reset balances!
              balances[msg.sender].currBalance += amount;
             
          }
      }
      else
      {
          revert();
      }
      
  }
  
  
  
  // Bot grabs balance from user's account
  function allocateBalance(uint amount, address user) public ifBot
  {
      // has user enough funds? remember this is being called by Backend!
      if (balances[user].currBalance >= amount)
      {
          balances[user].currBalance -= amount;
          balances[user].lockedBalance += amount; 
          if (bot.send(amount))
          {
            UserStatus('Bot has allocated balances', user, msg.value);
          }
          else
          {
              // if fail then reset state
              balances[user].currBalance += amount;
              balances[user].lockedBalance -= amount;
          }
      }
      
  }
  
  
  
  // SHARED BOT STUFF START
 
  
  // SHARED BOT STUFF END
  
  
  
  function deallocateBalance(address target) public payable ifBot 
  {
      // check if everything fine with bot value
      
      
      if (msg.value > balances[target].lockedBalance)
      {
          // profit has been made! Time to pay some fees!!11
          uint profit = msg.value - balances[target].lockedBalance;
          
          uint newFee = profit * fee/100;
          uint netProfit = profit - newFee;
          uint newBalance = balances[target].lockedBalance + netProfit;
          int vFee = int(newFee);
          
          if (balances[target].isInvestor == true)
          {
              
              
              // if user is investor and has credits left 
              if (balances[target].investorCredit > 0 )
              {
                  // deduct virtual balance
                  
                  balances[target].investorCredit -= vFee;
                  
                  if (balances[target].investorCredit < 0)
                  {
                      // credit is gone, recalculate profit
                      int toCalc = balances[target].investorCredit * -1;
                      uint newCalc = uint(toCalc);
                      profit -= newCalc; // deduct remaining fees
                      balances[target].currBalance += balances[target].lockedBalance + profit; // full profit gets added
                      balances[target].lockedBalance = 0; 
                      
                      balances[owner].currBalance += newCalc;
                  }
                  else
                  {
                    //UserStatus("investor credit deducted", target, vFee);
                     // add full profit 
                     balances[target].currBalance += balances[target].lockedBalance + profit; // full profit gets added
                     balances[target].lockedBalance = 0;    
                  }
                  
                  
              }
              else // if no credit left
              {
                  // get special fees ??
                  balances[target].currBalance += newBalance;
                  balances[target].lockedBalance = 0;
                  balances[owner].currBalance += newFee; // add fee to owner account
              }
          }
          else
          {
              balances[target].currBalance += newBalance;
              balances[target].lockedBalance = 0;
              balances[owner].currBalance += newFee;
          }
      }
      else
      {
          // no profit detected so no fees to pay!
          // platform looses some eth to gas though...!
          balances[target].lockedBalance = 0;
          balances[target].currBalance += msg.value;
          
      }
      
      
      
  }
  
  
   

  
  
  




}