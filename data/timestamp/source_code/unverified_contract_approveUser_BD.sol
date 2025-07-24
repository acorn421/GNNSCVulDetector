/*
 * ===== SmartInject Injection Details =====
 * Function      : approveUser
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
 * This modification introduces a stateful, multi-transaction Timestamp Dependence vulnerability through several mechanisms:
 * 
 * 1. **Time-Based Access Control**: The function now requires approvals to occur only during specific hours (8 AM to 8 PM UTC), using `block.timestamp % 86400` for daily time calculation. This is vulnerable to miner timestamp manipulation.
 * 
 * 2. **Rate Limiting Logic**: A flawed rate limiting system that calculates the "last approval time" based on current timestamp and registration count. This creates a dependency on accumulated state (registeredAccounts) that persists across transactions.
 * 
 * 3. **Timestamp Storage in State**: The approval timestamp is stored as a "bonus" in the user's currBalance, creating persistent state that can be manipulated.
 * 
 * **Multi-Transaction Exploitation**:
 * - **Transaction 1**: Owner calls approveUser() during valid hours, but the rate limiting can be bypassed by manipulating the timestamp
 * - **Transaction 2+**: Subsequent approvals can exploit the accumulated state where registeredAccounts affects the rate limiting calculation
 * - **Miner Manipulation**: Miners can manipulate block.timestamp within the 900-second tolerance to bypass both time restrictions and rate limits
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires the registeredAccounts state to accumulate across multiple approvals
 * - Each approval builds upon the previous state, creating opportunities for timestamp manipulation
 * - The rate limiting logic depends on the historical state of previous approvals
 * - Single transaction exploitation is impossible because the vulnerability depends on the accumulated registeredAccounts value and the relationship between multiple approval attempts
 * 
 * This creates a realistic vulnerability where the contract attempts to implement security controls but fails due to timestamp dependence and poor state management across multiple transactions.
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
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      // Store approval timestamp for time-based restrictions
      uint approvalTime = block.timestamp;
      
      // Only allow user approvals during "safe" hours (based on flawed timestamp logic)
      // This creates a vulnerability where miners can manipulate timestamps
      require(approvalTime % 86400 >= 28800 && approvalTime % 86400 <= 72000); // 8 AM to 8 PM UTC
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      balances[_user].user = _user;
      balances[_user].lockedBalance = 0;
      balances[_user].currBalance = 0;
      balances[_user].isInvestor = false;
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      // Implement a rate limiting mechanism using timestamp that accumulates state
      // This allows for multi-transaction exploitation
      if (registeredAccounts > 0) {
          uint lastApprovalTime = approvalTime - (registeredAccounts * 3600); // Simulate last approval time
          require(approvalTime >= lastApprovalTime + 3600); // Minimum 1 hour between approvals
      }
      
      registeredAccounts += 1;
      
      // Store the approval timestamp in a way that affects future operations
      // This creates persistent state that can be manipulated across transactions
      balances[_user].currBalance = approvalTime % 1000; // Store timestamp remnant as "bonus"
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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