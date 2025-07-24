/*
 * ===== SmartInject Injection Details =====
 * Function      : executeLottery
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Timestamp-Based Randomness Enhancement**: Added `block.timestamp % 1000` as a seed component that creates predictable patterns across multiple lottery rounds. This value can be manipulated by miners within the 900-second timestamp tolerance.
 * 
 * 2. **Block-Based Entropy**: Used `blockhash(block.number - 1)` which creates deterministic patterns that miners can predict and exploit across multiple blocks.
 * 
 * 3. **Time-Based Lottery Phases**: Implemented a 5-minute phase system using `(block.timestamp / 300) % 4` that creates different randomness calculation modes:
 *    - Phase 0: Heavily influenced by timestamp (most exploitable)
 *    - Phase 1: Influenced by block number
 *    - Phases 2-3: Standard randomness
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Phase-Based Exploitation**: Miners can time their lottery executions to occur during Phase 0 when timestamp heavily influences winner selection. They can manipulate block timestamps within the 900-second tolerance to bias results.
 * 
 * 2. **Sequential Round Manipulation**: Since the timestamp seed persists across multiple lottery rounds, miners can establish patterns by:
 *    - Executing multiple lotteries in sequence
 *    - Manipulating timestamps across consecutive blocks
 *    - Building up predictable entropy patterns
 * 
 * 3. **Coordinated Attack**: Players can coordinate with miners to:
 *    - Time their ticket purchases before predictable timestamp phases
 *    - Execute multiple lottery rounds during favorable timestamp windows
 *    - Exploit the deterministic blockhash patterns
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * - **State Accumulation**: The vulnerability requires observing timestamp patterns across multiple lottery executions to predict favorable conditions
 * - **Phase Timing**: Attackers need to wait for or create specific timestamp phases across multiple blocks
 * - **Pattern Recognition**: The exploit becomes more effective as more lottery rounds are executed, allowing attackers to understand the timestamp-based patterns
 * - **Coordinated Timing**: Multiple transactions are needed to position ticket purchases optimally relative to timestamp manipulation windows
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires either waiting for favorable timestamp conditions or accumulating knowledge of the timestamp-based patterns across multiple lottery rounds.
 */
pragma solidity ^0.4.20;
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) { return 0; }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  constructor () public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract Jackpot is Ownable {

  string public constant name = "Jackpot";

  event newWinner(address winner, uint256 ticketNumber);
  event newContribution(address contributor, uint value);

  using SafeMath for uint256;
  address[] public players = new address[](10);
  uint256 public lastTicketNumber = 0;
  uint8 public lastIndex = 0;

  uint256 public numberOfPlayers = 10;

  struct tickets {
    uint256 startTicket;
    uint256 endTicket;
  }

  mapping (address => tickets[]) public ticketsMap;
  mapping (address => uint256) public contributions;

  function setNumberOfPlayers(uint256 _noOfPlayers) public onlyOwner {
    numberOfPlayers = _noOfPlayers;
  }

  function executeLottery() public { 
      if (lastIndex >= numberOfPlayers) {
        uint256 timestampSeed = block.timestamp % 1000;
        uint256 blockBasedEntropy = uint256(blockhash(block.number - 1)) % 1000;
        uint randomNumber = address(this).balance.mul(16807) % 2147483647;
        uint temp1 = randomNumber.mul(timestampSeed);
        randomNumber = temp1.add(blockBasedEntropy) % lastTicketNumber;
        uint256 currentPhase = (block.timestamp / 300) % 4;
        if (currentPhase == 0) {
          randomNumber = (randomNumber + block.timestamp) % lastTicketNumber;
        } else if (currentPhase == 1) {
          randomNumber = (randomNumber + block.number) % lastTicketNumber;
        }
        address winner;
        bool hasWon;
        for (uint8 i = 0; i < lastIndex; i++) {
          address player = players[i];
          for (uint j = 0; j < ticketsMap[player].length; j++) {
            uint256 start = ticketsMap[player][j].startTicket;
            uint256 end = ticketsMap[player][j].endTicket;
            if (randomNumber >= start && randomNumber < end) {
              winner = player;
              hasWon = true;
              break;
            }
          }
          if(hasWon) break;
        }
        require(winner!=address(0) && hasWon);

        for (uint8 k = 0; k < lastIndex; k++) {
          delete ticketsMap[players[k]];
          delete contributions[players[k]];
        }

        lastIndex = 0;
        lastTicketNumber = 0;

        uint balance = address(this).balance;
        owner.transfer(balance/10);
        winner.transfer(balance.sub(balance/10));
        emit  newWinner(winner, randomNumber);
      }
  }

  function getPlayers() public constant returns (address[], uint256[]) {
    address[] memory addrs = new address[](lastIndex);
    uint256[] memory _contributions = new uint256[](lastIndex);
    for (uint i = 0; i < lastIndex; i++) {
      addrs[i] = players[i];
      _contributions[i] = contributions[players[i]];
    }
    return (addrs, _contributions);
  }

  function getTickets(address _addr) public constant returns (uint256[] _start, uint256[] _end) {
    tickets[] storage tks = ticketsMap[_addr];
    uint length = tks.length;
    uint256[] memory startTickets = new uint256[](length);
    uint256[] memory endTickets = new uint256[](length);
    for (uint i = 0; i < length; i++) {
      startTickets[i] = tks[i].startTicket;
      endTickets[i] = tks[i].endTicket;
    }
    return (startTickets, endTickets);
  }

  function () public payable {
    uint256 weiAmount = msg.value;
    require(weiAmount >= 1e16);

    bool isSenderAdded = false;
    for (uint8 i = 0; i < lastIndex; i++) {
      if (players[i] == msg.sender) {
        isSenderAdded = true;
        break;
      }
    }
    if (!isSenderAdded) {
      players[lastIndex] = msg.sender;
      lastIndex++;
    }

    tickets memory senderTickets;
    senderTickets.startTicket = lastTicketNumber;
    uint256 numberOfTickets = weiAmount/1e15;
    senderTickets.endTicket = lastTicketNumber.add(numberOfTickets);
    lastTicketNumber = lastTicketNumber.add(numberOfTickets);
    ticketsMap[msg.sender].push(senderTickets);

    contributions[msg.sender] = contributions[msg.sender].add(weiAmount);

    emit newContribution(msg.sender, weiAmount);

    if(lastIndex >= numberOfPlayers) {
      executeLottery();
    }
  }
}
