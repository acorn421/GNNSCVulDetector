/*
 * ===== SmartInject Injection Details =====
 * Function      : bet
 * Vulnerability : Timestamp Dependence
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
 * Introduced a multi-transaction timestamp dependence vulnerability through time-based betting mechanics:
 * 
 * 1. **State Variables Added**: Four new state variables track time-dependent features:
 *    - `lastJackpotTime`: Tracks when jackpot accumulation started
 *    - `jackpotAccumulator`: Accumulates jackpot value over time
 *    - `lastBetTimestamp`: Global timestamp of last bet
 *    - `playerLastBetTime`: Maps player addresses to their last bet timestamp
 * 
 * 2. **Time-Based Betting Cooldown**: Players must wait 60 seconds between bets, enforced using `block.timestamp`. This creates a multi-transaction vulnerability where miners can manipulate timestamps to bypass cooldowns.
 * 
 * 3. **Jackpot Accumulation System**: The jackpot grows over time based on elapsed time calculations using `block.timestamp`. This requires multiple transactions to build up the jackpot value before it can be claimed.
 * 
 * 4. **Time-Triggered Jackpot Release**: Jackpot is only released when 1 hour (3600 seconds) has passed since `lastJackpotTime`, creating a multi-transaction dependency where:
 *    - Transaction 1: Initialize jackpot timing
 *    - Transaction 2+: Accumulate jackpot over time
 *    - Final Transaction: Trigger jackpot release after time threshold
 * 
 * **Multi-Transaction Exploitation**:
 * - **Transaction 1**: Attacker places initial bet to set `lastJackpotTime`
 * - **Transaction 2**: Attacker (as miner) manipulates `block.timestamp` to make it appear significant time has passed, accumulating large jackpot
 * - **Transaction 3**: Attacker places winning bet with manipulated timestamp to trigger jackpot release and claim accumulated rewards
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability depends on state persistence across transactions (jackpot accumulation)
 * - Time-based conditions require sequential transactions to build up exploitable state
 * - The exploit cannot be executed atomically - it requires the state changes from previous transactions to be effective
 * - Miners must coordinate across multiple blocks to manipulate timestamps effectively
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

contract SPACEDICE is Mortal, usingNRE {
  uint minBet = 1000000000000000; //.001 ETH minimum bet 

  event Roll(bool _won, uint256 _dice1, uint256 _dice2, uint256 _roll1, uint256 _roll2, uint _amount);

  constructor() payable public {}

  function() public { //fallback
    revert();
  }

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
  // Add new state variables to track time-based features
  uint256 public lastJackpotTime;
  uint256 public jackpotAccumulator;
  uint256 public lastBetTimestamp;
  mapping(address => uint256) public playerLastBetTime;
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  function bet(uint _diceOne, uint _diceTwo) payable public {
    require(tx.origin == msg.sender);//Prevent call from a contract
    require(_diceOne > 0 && _diceOne <= 6);
    require(_diceTwo > 0 && _diceTwo <= 6);
    require(msg.value >= minBet);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based betting cooldown - vulnerable to timestamp manipulation
    require(block.timestamp >= playerLastBetTime[msg.sender] + 60, "Must wait 60 seconds between bets");
    playerLastBetTime[msg.sender] = block.timestamp;
    
    // Jackpot accumulation over time - updates state across transactions
    if (lastJackpotTime == 0) {
        lastJackpotTime = block.timestamp;
    }
    
    // Accumulate jackpot based on time elapsed - vulnerable to timestamp manipulation
    uint256 timeElapsed = block.timestamp - lastJackpotTime;
    if (timeElapsed > 0) {
        jackpotAccumulator += (msg.value * timeElapsed) / 3600; // Grows per hour
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    uint256 rollone = ra() % 6 + 1;
    uint256 rolltwo = rx() % 6 + 1;
    uint256 totalroll = rollone + rolltwo;
    uint256 totaldice = _diceOne + _diceTwo;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if (totaldice == totalroll) {
      uint amountWon = msg.value*2;//Pays double for total call
      if(rollone==rolltwo && _diceOne==_diceTwo) amountWon = msg.value*8;//Pays x8 for hard ways
      if(totalroll==2 || totalroll==12) amountWon = msg.value*30;//Pays x30 for 11 or 66
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Time-based jackpot trigger - vulnerable to timestamp manipulation
      if (block.timestamp >= lastJackpotTime + 3600 && jackpotAccumulator > 0) {
          amountWon += jackpotAccumulator;
          jackpotAccumulator = 0;
          lastJackpotTime = block.timestamp;
      }
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      if(!msg.sender.send(amountWon)) revert();
      emit Roll(true, _diceOne, _diceTwo, rollone, rolltwo, amountWon);
    }
    else {
      emit Roll(false, _diceOne, _diceTwo, rollone, rolltwo, 0);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Update global bet timestamp for jackpot calculations
    lastBetTimestamp = block.timestamp;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
