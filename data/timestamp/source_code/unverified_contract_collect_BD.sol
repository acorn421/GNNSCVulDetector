/*
 * ===== SmartInject Injection Details =====
 * Function      : collect
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based withdrawal limits that rely on block.timestamp. The vulnerability requires state variables (lastWithdrawalTime, dailyWithdrawnAmount) that must be declared at contract level. The exploit involves miners manipulating block.timestamp across multiple transactions to bypass daily withdrawal limits. First transaction sets the withdrawal timestamp, subsequent transactions can exploit timestamp manipulation to reset the daily limit prematurely, allowing excessive withdrawals. The vulnerability is stateful because it depends on accumulated withdrawal amounts and timestamps persisting between transactions, and multi-transaction because it requires at least two separate calls to exploit the timing manipulation.
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

  uint public lastWithdrawalTime;
  uint public dailyWithdrawnAmount;

  constructor() payable public {}

  function() public { //fallback
    revert();
  }

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
      if(!msg.sender.send(amountWon)) revert();
      emit Roll(true, _diceOne, _diceTwo, rollone, rolltwo, amountWon);
    }
    else {
      emit Roll(false, _diceOne, _diceTwo, rollone, rolltwo, 0);
    }
  }

  function checkContractBalance() public view returns(uint) {
    return address(this).balance;
  }

  //Withdrawal function
  function collect(uint _amount) public onlyOwner {
    require(address(this).balance > _amount);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based withdrawal limits with timestamp dependence vulnerability
    if (lastWithdrawalTime == 0) {
        lastWithdrawalTime = block.timestamp;
        dailyWithdrawnAmount = 0;
    }
    
    // Reset daily limit if 24 hours have passed
    if (block.timestamp >= lastWithdrawalTime + 1 days) {
        dailyWithdrawnAmount = 0;
        lastWithdrawalTime = block.timestamp;
    }
    
    uint maxDailyWithdrawal = address(this).balance / 10; // 10% of balance per day
    require(dailyWithdrawnAmount + _amount <= maxDailyWithdrawal, "Daily withdrawal limit exceeded");
    
    dailyWithdrawnAmount += _amount;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    owner.transfer(_amount);
  }
}
