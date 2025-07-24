/*
 * ===== SmartInject Injection Details =====
 * Function      : deallocateBalance
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-eth (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to the target address before critical state updates. The vulnerability allows the target to re-enter the function during the callback and manipulate state based on intermediate values. This requires multiple transactions to exploit: first to set up the state (lockedBalance, investorCredit), then to trigger the callback that can re-enter and exploit the inconsistent state between the profit calculation and final balance updates.
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added External Calls**: Inserted `target.call.value(0)(bytes4(keccak256("onProfitReceived(uint256)")), profit/netProfit)` callbacks before state finalization in all profit-making branches.
 * 
 * 2. **Timing of Calls**: The external calls are strategically placed after profit calculations but before final balance updates, creating a reentrancy window where state is inconsistent.
 * 
 * 3. **State Exploitation Window**: During the callback, the target can observe that:
 *    - `investorCredit` has been modified
 *    - `lockedBalance` is still non-zero
 *    - `currBalance` hasn't been updated yet
 *    - Profit calculations have been performed but not committed
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Target calls `depositFunds()` to establish `currBalance`
 * - Bot calls `allocateBalance()` to move funds to `lockedBalance`
 * - Target deploys a malicious contract that implements `onProfitReceived()`
 * 
 * **Transaction 2 (Exploitation)**:
 * - Bot calls `deallocateBalance()` with profit
 * - Function calculates profit and modifies `investorCredit`
 * - Function calls `target.onProfitReceived()` before updating balances
 * - Target's malicious contract re-enters `deallocateBalance()` with different parameters
 * - Re-entrant call sees modified `investorCredit` but unchanged `lockedBalance`
 * - Can manipulate the profit calculation logic or trigger multiple payouts
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on accumulated state from previous transactions (locked balances, investor credits, deposited funds).
 * 
 * 2. **Contract Deployment**: The target needs to deploy a malicious contract with `onProfitReceived()` function beforehand.
 * 
 * 3. **Sequential Dependencies**: The exploit requires specific state setup that can only be achieved through multiple function calls across different transactions.
 * 
 * 4. **Timing Constraints**: The reentrancy window only exists during the callback, which happens after state has been partially modified in the current transaction.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world patterns where external notifications or callbacks create reentrancy opportunities in financial smart contracts.
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



  function CryptoRushContract()
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
      throw;
    }
    _;
  }
  
  modifier ifBot()
  {
    if (msg.sender != bot)
    {
      throw;
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
        throw;
    }
  }
  
  
  function closeContract() ifOwner
  {
      suicide(owner);
  }
  
  // placeholder in case I manage to implement an auto-updater for V1
  function updateContract() ifOwner
  {
      
  }
  
  // only owner can approve new User and currently owner can't remove user once registered.
  // Transparency and Trust yaaay!
  function approveUser(address _user) ifOwner
  {
      balances[_user].user = _user;
      balances[_user].lockedBalance = 0;
      balances[_user].currBalance = 0;
      balances[_user].isInvestor = false;
      
      registeredAccounts += 1;
  }
  
  function approveAsInvestor(address _user, int _investorCredit) ifOwner
  {
      balances[_user].user = _user;
      balances[_user].isInvestor = true;
      balances[_user].investorCredit = _investorCredit;
      
  }
  
  
  
  // only allow call from owner of the address asking
  function getCurrBalance() constant returns (uint _balance)
  {
      if(balances[msg.sender].user == msg.sender)
      {
        return balances[msg.sender].currBalance;    
      }
      else
      {
          throw;
      }
      
  }
  
  // only allow call from owner of the address asking
  function getLockedBalance() constant returns (uint _balance)
  {
      if(balances[msg.sender].user == msg.sender)
      {
        return balances[msg.sender].lockedBalance;    
      }
      else
      {
          throw;
      }
      
  }
  
  // only allow call from owner of the address asking
  function getInvestorCredit() constant returns (int _balance)
  {
      if(balances[msg.sender].user == msg.sender)
      {
        return balances[msg.sender].investorCredit;    
      }
      else
      {
          throw;
      }
      
  }
  

  // default deposit function used by Users
  function depositFunds() payable
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

 

  function withdrawFunds (uint amount) ifApproved
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
          throw;
      }
      
  }
  
  
  
  // Bot grabs balance from user's account
  function allocateBalance(uint amount, address user) ifBot
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
  
  
  
  function deallocateBalance(address target) payable ifBot 
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
                      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                      
                      // Notify the target about profit before finalizing state
                      if (target.call.value(0)(bytes4(keccak256("onProfitReceived(uint256)")), profit)) {
                          // Callback successful
                      }
                      
                      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                      balances[target].currBalance += balances[target].lockedBalance + profit; // full profit gets added
                      balances[target].lockedBalance = 0; 
                      
                      balances[owner].currBalance += newCalc;
                  }
                  else
                  {
                    //UserStatus("investor credit deducted", target, vFee);
                     // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                     
                     // Notify the target about profit before finalizing state  
                     if (target.call.value(0)(bytes4(keccak256("onProfitReceived(uint256)")), profit)) {
                         // Callback successful
                     }
                     
                     // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                     // add full profit 
                     balances[target].currBalance += balances[target].lockedBalance + profit; // full profit gets added
                     balances[target].lockedBalance = 0;    
                  }
                  
                  
              }
              else // if no credit left
              {
                  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                  // Notify the target about profit before finalizing state
                  if (target.call.value(0)(bytes4(keccak256("onProfitReceived(uint256)")), netProfit)) {
                      // Callback successful
                  }
                  
                  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                  // get special fees ??
                  balances[target].currBalance += newBalance;
                  balances[target].lockedBalance = 0;
                  balances[owner].currBalance += newFee; // add fee to owner account
              }
          }
          else
          {
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              // Notify the target about profit before finalizing state
              if (target.call.value(0)(bytes4(keccak256("onProfitReceived(uint256)")), netProfit)) {
                  // Callback successful
              }
              
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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