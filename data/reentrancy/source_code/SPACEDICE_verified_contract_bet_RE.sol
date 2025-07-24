/*
 * ===== SmartInject Injection Details =====
 * Function      : bet
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
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTED**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variable**: Introduced `mapping(address => uint256) public pendingWithdrawals;` to track accumulated winnings per user
 * 2. **Modified Winning Logic**: Replaced immediate `msg.sender.send(amountWon)` with `pendingWithdrawals[msg.sender] += amountWon;`
 * 3. **Added Withdrawal Function**: Created separate `withdraw()` function with classic reentrancy vulnerability pattern
 * 4. **Vulnerable External Call**: The `withdraw()` function calls `msg.sender.call.value(amount)("")` before updating state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: User calls `bet()` and wins, accumulating winnings in `pendingWithdrawals[user] = 100 ETH`
 * **Transaction 2**: User calls `withdraw()` which triggers the vulnerability:
 * - `amount = pendingWithdrawals[user]` (100 ETH)
 * - External call `msg.sender.call.value(100)("")` is made
 * - If user has a fallback function, it can call `withdraw()` again recursively
 * - Since `pendingWithdrawals[msg.sender] = 0` happens after the external call, the mapping still shows 100 ETH
 * - User can drain more than their legitimate winnings
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Accumulation**: The vulnerability requires users to first build up a `pendingWithdrawals` balance through successful betting (Transaction 1)
 * 2. **Separate Exploitation**: The reentrancy attack occurs in a separate `withdraw()` call (Transaction 2)
 * 3. **Stateful Persistence**: The `pendingWithdrawals` mapping persists between transactions, enabling the accumulated state to be exploited later
 * 4. **Cannot Be Exploited in Single Transaction**: A user cannot exploit this in one transaction because they need to first win bets to build up withdrawable balance, then separately call withdraw() to exploit the reentrancy
 * 
 * **Realistic Production Pattern**: This follows the common "withdrawal pattern" used in many DeFi protocols where winnings/earnings are credited to user balances and require separate withdrawal calls, making it a highly realistic vulnerability injection.
 */
//SPACEDICE - https://adapp.games/spacedice
//Pick dice 1, dice 2, and place a minimum bet of .001 ETH
//Pays x2 for total call, x8 for hard ways, x30 for snake eyes or midnight

pragma solidity ^0.4.23;

//Randomness by Ñíguez Randomity Engine
//https://niguezrandomityengine.github.io/
contract niguezRandomityEngine {
  function ra() external view returns (uint256);
  function rx() external view returns (uint256);
}

contract usingNRE {
  niguezRandomityEngine internal nre = niguezRandomityEngine(0x031eaE8a8105217ab64359D4361022d0947f4572);
    
  function ra() internal view returns (uint256) {
        return nre.ra();
    }
    
  function rx() internal view returns (uint256) {
        return nre.rx();
    }
}

contract Ownable {
  address owner;
  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner {
    require(msg.sender == owner);
    _;
  }
}

contract Mortal is Ownable {
  function kill() public onlyOwner {
    selfdestruct(owner);
  }
}

contract SPACEDICE is Mortal, usingNRE{
  uint minBet = 1000000000000000; //.001 ETH minimum bet 

  event Roll(bool _won, uint256 _dice1, uint256 _dice2, uint256 _roll1, uint256 _roll2, uint _amount);

  constructor() payable public {}

  function() public { //fallback
    revert();
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => uint256) public pendingWithdrawals;
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  function bet(uint _diceOne, uint _diceTwo) payable public {
    require(tx.origin == msg.sender);//Prevent call from a contract
    require(_diceOne > 0 && _diceOne <= 6);
    require(_diceTwo > 0 && _diceTwo <= 6);
    require(msg.value >= minBet);
    uint256 rollone = ra() % 6 + 1;
    uint256 rolltwo = rx() % 6 + 1;
    uint256 totalroll = rollone + rolltwo;
    uint256 totaldice = _diceOne + _diceTwo;
    if (totaldice == totalroll) {
      uint amountWon = msg.value*2;//Pays double for total call
      if(rollone==rolltwo && _diceOne==_diceTwo) amountWon = msg.value*8;//Pays x8 for hard ways
      if(totalroll==2 || totalroll==12) amountWon = msg.value*30;//Pays x30 for 11 or 66
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Credit winnings to user's pending balance instead of immediate payment
      pendingWithdrawals[msg.sender] += amountWon;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      emit Roll(true, _diceOne, _diceTwo, rollone, rolltwo, amountWon);
    }
    else {
      emit Roll(false, _diceOne, _diceTwo, rollone, rolltwo, 0);
    }
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  function withdraw() public {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "No pending withdrawals");
    // VULNERABILITY: External call before state update
    // This allows reentrancy where user can call withdraw() multiple times
    // before pendingWithdrawals is reset to 0
    if (msg.sender.call.value(amount)("")) {
      pendingWithdrawals[msg.sender] = 0; // State update after external call
    }
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  function checkContractBalance() public view returns(uint) {
    return address(this).balance;
  }

  //Withdrawal function
  function collect(uint _amount) public onlyOwner {
    require(address(this).balance > _amount);
    owner.transfer(_amount);
  }
}
