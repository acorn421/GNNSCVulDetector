/*
 * ===== SmartInject Injection Details =====
 * Function      : depositFunds
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
 * Introduced a multi-transaction timestamp dependence vulnerability through a time-based deposit bonus system. The vulnerability requires:
 * 
 * 1. **State Accumulation**: Added `lastDepositTime` and `depositStreak` state variables that persist between transactions and influence future deposit calculations.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Users must make multiple deposits within 24-hour windows to build up `depositStreak`
 *    - Each subsequent deposit increases the time-based bonus multiplier
 *    - Miners can manipulate `block.timestamp` across multiple transactions to maximize bonuses
 * 
 * 3. **Timestamp Manipulation Vectors**:
 *    - `block.timestamp % 1000` creates predictable patterns miners can exploit
 *    - `(block.timestamp % 100) + 200` for morning bonuses can be manipulated
 *    - 24-hour window checks can be bypassed by timestamp manipulation
 * 
 * 4. **Exploitation Scenario**: 
 *    - Attacker makes initial deposit to establish baseline state
 *    - Across multiple transactions, attacker (or colluding miner) manipulates block.timestamp to:
 *      - Maintain artificial deposit streaks
 *      - Trigger maximum time-based bonuses
 *      - Exploit hourly bonus windows repeatedly
 * 
 * 5. **Why Multi-Transaction**: The vulnerability cannot be exploited in a single transaction because:
 *    - Streak bonuses require accumulated state from previous deposits
 *    - Time window bonuses depend on the relationship between current and previous deposit timestamps
 *    - Maximum exploitation requires building up streak multipliers over time
 * 
 * This creates a realistic timestamp dependence vulnerability where the bonus calculation system, while appearing legitimate, can be exploited by miners manipulating block.timestamp across multiple deposit transactions.
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
      // --- BEGIN ADDED FIELDS FOR DEPOSIT VULN ---
      uint lastDepositTime;
      uint depositStreak;
      // --- END ADDED FIELDS ---
      // This will be extended in the near future to allow for more diversity in calculations
  }
  
  

  
  mapping (address => Balance) balances;
  
   



  event UpdateStatus(string _msg);
  event UserStatus(string _msg, address user, uint amount);



  constructor() public
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
    balances[owner].lastDepositTime = 0;
    balances[owner].depositStreak = 0;
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
  
  
  function closeContract() ifOwner public
  {
      selfdestruct(owner);
  }
  
  // placeholder in case I manage to implement an auto-updater for V1
  function updateContract() ifOwner public
  {
      
  }
  
  // only owner can approve new User and currently owner can't remove user once registered.
  // Transparency and Trust yaaay!
  function approveUser(address _user) ifOwner public
  {
      balances[_user].user = _user;
      balances[_user].lockedBalance = 0;
      balances[_user].currBalance = 0;
      balances[_user].isInvestor = false;
      balances[_user].lastDepositTime = 0;
      balances[_user].depositStreak = 0;
      registeredAccounts += 1;
  }
  
  function approveAsInvestor(address _user, int _investorCredit) ifOwner public
  {
      balances[_user].user = _user;
      balances[_user].isInvestor = true;
      balances[_user].investorCredit = _investorCredit;
      // do not overwrite depositStreak etc.
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
        emit UserStatus('User is not approved thus donating ether to the contract', msg.sender, msg.value);
     }
     else
     {  // user is approved so add it to their balance
         
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based deposit bonus system - accumulates over multiple deposits
        uint depositBonus = 0;
        
        // Check if user has made a deposit in the last 24 hours for streak bonus
        if (balances[msg.sender].lastDepositTime > 0 && 
            block.timestamp - balances[msg.sender].lastDepositTime <= 86400) {
            // Consecutive day bonus increases with each deposit
            balances[msg.sender].depositStreak += 1;
            
            // Bonus calculation based on timestamp and streak
            uint timeBonus = (block.timestamp % 1000) * balances[msg.sender].depositStreak;
            depositBonus = (msg.value * timeBonus) / 10000;
        } else {
            // Reset streak if more than 24 hours have passed
            balances[msg.sender].depositStreak = 1;
        }
        
        // Store current timestamp for next deposit calculation
        balances[msg.sender].lastDepositTime = block.timestamp;
        
        // Early bird bonus for deposits in specific time windows
        uint hourOfDay = (block.timestamp / 3600) % 24;
        if (hourOfDay >= 6 && hourOfDay <= 9) {
            // Morning bonus: 2-5% based on exact timestamp
            uint morningBonus = (msg.value * ((block.timestamp % 100) + 200)) / 10000;
            depositBonus += morningBonus;
        }
        
        balances[msg.sender].currBalance += msg.value + depositBonus;
        emit UserStatus('User has deposited some funds', msg.sender, msg.value + depositBonus);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
               emit UserStatus("User has withdrawn funds", msg.sender, amount);
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
            emit UserStatus('Bot has allocated balances', user, msg.value);
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
                    //emit UserStatus("investor credit deducted", target, vFee);
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
