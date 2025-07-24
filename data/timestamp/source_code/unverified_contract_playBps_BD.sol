/*
 * ===== SmartInject Injection Details =====
 * Function      : playBps
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 26 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a multi-transaction timestamp dependence vulnerability through several mechanisms:
 * 
 * 1. **Timestamp-based Speed Bonus**: Added logic that rewards players with double coins if they play within 60 seconds of the last move, using block.timestamp comparison. This creates manipulation opportunities for miners.
 * 
 * 2. **Block Number Advantage Accumulation**: Implemented a system where players accumulate advantages based on playing in consecutive blocks (block.number differences). This advantage persists across multiple transactions in the playerAdvantage mapping.
 * 
 * 3. **Timestamp-based Pseudo-randomness**: Added vulnerable randomness generation using block.timestamp, block.difficulty, and msg.sender that can be manipulated by miners to influence game outcomes.
 * 
 * 4. **Stateful Advantage System**: The playerAdvantage mapping maintains state across transactions, allowing accumulated advantages to influence future game results.
 * 
 * The vulnerability requires multiple transactions to exploit:
 * - First transaction: Establish timing/block baselines and begin accumulating advantages
 * - Subsequent transactions: Exploit the accumulated state and timing manipulation for unfair wins
 * 
 * Miners can manipulate block timestamps and coordinate transaction timing across multiple blocks to gain unfair advantages that persist in contract state.
 */
pragma solidity ^0.4.3;

 /**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {

  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
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
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
// ----------------------------------------------------------------------------
contract ERC20Interface {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

contract BlockPaperScissors is Ownable {

  using SafeMath for uint256;

    ERC20Interface bCoin;
    ERC20Interface pCoin;
    ERC20Interface sCoin;
    ERC20Interface tCoin;

    address public rpsDev = msg.sender;
    uint8 public lastMove = 1; // last played move; 1=rock, 2=paper, 3=scissor
    address public lastPlayer = msg.sender;
    uint public oneCoin = 1000000000000000000;
    // State variables needed by playBps
    uint256 public lastMoveTimestamp;
    uint256 public lastMoveBlock;
    mapping(address => uint256) public playerAdvantage;

//FUNCTIONS setting and retrieving global variables that impact gameplay

    function setBCoinContractAddress(address _address) external onlyOwner {
      bCoin = ERC20Interface(_address);
    }
    function setPCoinContractAddress(address _address) external onlyOwner {
      pCoin = ERC20Interface(_address);
    }
    function setSCoinContractAddress(address _address) external onlyOwner {
      sCoin = ERC20Interface(_address);
    }
    function setTCoinContractAddress(address _address) external onlyOwner {
      tCoin = ERC20Interface(_address);
    }

//EVENTS

    event newMove(uint8 move);
    event newWinner(address winner);

// FUNCTIONS interacting with the swine structs in contract

    function playBps(uint8 _choice) public returns (uint8) {
      require (_choice == 1 || _choice == 2 || _choice == 3);
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Timestamp-based speed bonus: reward quick play within 60 seconds
      uint256 timeDiff = block.timestamp - lastMoveTimestamp;
      uint256 bonusMultiplier = 1;
      if (timeDiff <= 60 && lastMoveTimestamp > 0) {
        bonusMultiplier = 2; // Double reward for quick play
      }
      
      // Accumulate timing-based advantage based on block number differences
      if (lastMoveBlock > 0) {
        uint256 blockDiff = block.number - lastMoveBlock;
        if (blockDiff <= 3) {
          // Player gets advantage for playing in consecutive blocks
          playerAdvantage[msg.sender] += blockDiff;
        }
      }
      
      if (_choice == lastMove) {
        tCoin.transfer(msg.sender, oneCoin.mul(bonusMultiplier));
        tCoin.transfer(lastPlayer, oneCoin.mul(bonusMultiplier));// send tie token to each player
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        setGame(_choice, msg.sender);
        return 3; // it's a tie
      }
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Use timestamp-based pseudo-randomness for tie-breaking when player has accumulated advantage
      uint256 advantage = playerAdvantage[msg.sender];
      bool hasAdvantage = false;
      if (advantage > 0) {
        // Vulnerable timestamp-based randomness
        uint256 randomness = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 100;
        if (randomness < advantage * 10) { // 10% chance per advantage point
          hasAdvantage = true;
        }
      }
      
      if (_choice == 1) { //choice is block
        if (lastMove == 3 || hasAdvantage) {
          bCoin.transfer(msg.sender, oneCoin.mul(bonusMultiplier));
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          pCoin.transfer(lastPlayer, oneCoin.mul(bonusMultiplier));
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
      if (_choice == 2) { // choice is paper
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        if (lastMove == 1 || hasAdvantage) {
          pCoin.transfer(msg.sender, oneCoin.mul(bonusMultiplier));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          sCoin.transfer(lastPlayer, oneCoin.mul(bonusMultiplier));
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
      if (_choice == 3) { // choice is scissors
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        if (lastMove == 2 || hasAdvantage) {
          sCoin.transfer(msg.sender, oneCoin.mul(bonusMultiplier));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          bCoin.transfer(lastPlayer, oneCoin.mul(bonusMultiplier));
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
    }

    function setGame(uint8 _move, address _player) private {
      lastMove = _move;
      lastPlayer = _player;
      lastMoveTimestamp = block.timestamp;
      lastMoveBlock = block.number;
      newMove(_move);
    }

}

library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }

}