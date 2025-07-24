/*
 * ===== SmartInject Injection Details =====
 * Function      : setMaintenanceMode
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where the contract relies on 'now' (block.timestamp) for maintenance mode timing. The vulnerability is stateful and multi-transaction: 1) Owner calls setMaintenanceMode() to activate maintenance, 2) Time passes, 3) Owner calls exitMaintenanceMode() or emergencyExitMaintenance() to exit maintenance. A malicious miner could manipulate block timestamps to either extend or shorten maintenance periods, potentially affecting contract availability or allowing premature exits from maintenance mode.
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


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public maintenanceEndTime;
    bool public maintenanceMode = false;
    
    function setMaintenanceMode(uint _durationMinutes) public onlyOwner {
        maintenanceMode = true;
        maintenanceEndTime = now + (_durationMinutes * 60);
    }
    
    function exitMaintenanceMode() public onlyOwner {
        require(now >= maintenanceEndTime);
        maintenanceMode = false;
    }
    
    function emergencyExitMaintenance() public onlyOwner {
        require(now >= maintenanceEndTime - 300); // Can exit 5 minutes early
        maintenanceMode = false;
    }
    // === END FALLBACK INJECTION ===

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
    owner.transfer(_amount);
  }
}