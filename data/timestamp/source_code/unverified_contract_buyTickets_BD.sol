/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTickets
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based bonus ticket allocation system. The vulnerability uses block.timestamp % 300 < 60 to create 60-second windows every 5 minutes where users can get free bonus tickets. This creates a predictable timestamp-dependent advantage that attackers can exploit by timing their transactions to occur during these favorable windows. The vulnerability is stateful because it affects ticket allocation across the entire raffle, and multi-transaction because an attacker needs to: 1) Monitor the blockchain for favorable timestamp windows, 2) Execute multiple buyTickets() transactions timed to exploit these windows, 3) Accumulate more tickets than intended through repeated exploitation across multiple transactions. The vulnerability persists across the entire raffle lifecycle, allowing sophisticated attackers to gain unfair advantages through timestamp manipulation.
 */
pragma solidity ^0.4.0;

contract Ethraffle {
    // Structs
    struct Contestant {
        address addr;
        uint raffleId;
    }

    // Constants
    address public creatorAddress;
    address constant public rakeAddress = 0x15887100f3b3cA0b645F007c6AA11348665c69e5;
    uint constant public prize = 0.1 ether;
    uint constant public rake = 0.02 ether;
    uint constant public totalTickets = 6;
    uint constant public pricePerTicket = (prize + rake) / totalTickets;

    // Variables
    uint public raffleId = 0;
    uint public nextTicket = 0;
    uint public lastWinningNumber = 0;
    mapping (uint => Contestant) public contestants;
    uint[] public gaps;

    // Initialization
    function Ethraffle() public {
        creatorAddress = msg.sender;
        resetRaffle();
    }

    function resetRaffle() private {
        raffleId++;
        nextTicket = 1;
    }

    // Call buyTickets() when receiving Ether outside a function
    function () payable public {
        buyTickets();
    }

    function buyTickets() payable public {
        uint moneySent = msg.value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based ticket allocation bonus - store purchase timestamp for later advantage
        uint currentTime = block.timestamp;
        uint timeBonus = 0;
        
        // Check if this purchase qualifies for time-based bonus tickets
        if (currentTime % 300 < 60) { // First minute of every 5-minute window
            timeBonus = 1;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        while (moneySent >= pricePerTicket && nextTicket <= totalTickets) {
            uint currTicket = 0;
            if (gaps.length > 0) {
                currTicket = gaps[gaps.length-1];
                gaps.length--;
            } else {
                currTicket = nextTicket++;
            }

            contestants[currTicket] = Contestant(msg.sender, raffleId);
            moneySent -= pricePerTicket;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Apply time bonus by purchasing additional tickets if qualified
        while (timeBonus > 0 && nextTicket <= totalTickets) {
            uint bonusTicket = 0;
            if (gaps.length > 0) {
                bonusTicket = gaps[gaps.length-1];
                gaps.length--;
            } else {
                bonusTicket = nextTicket++;
            }
            
            contestants[bonusTicket] = Contestant(msg.sender, raffleId);
            timeBonus--;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        // Choose winner if we sold all the tickets
        if (nextTicket > totalTickets) {
            chooseWinner();
        }

        // Send back leftover money
        if (moneySent > 0) {
            msg.sender.transfer(moneySent);
        }
    }

    function chooseWinner() private {
        uint winningTicket = getRandom();
        lastWinningNumber = winningTicket;
        address winningAddress = contestants[winningTicket].addr;
        resetRaffle();
        winningAddress.transfer(prize);
        rakeAddress.transfer(rake);
    }

    // Choose a random int between 1 and totalTickets
    function getRandom() private returns (uint) {
        return (uint(sha3(
          block.timestamp +
          block.number +
          block.gaslimit +
          block.difficulty +
          msg.gas +
          uint(msg.sender) +
          uint(block.coinbase)
        )) % totalTickets) + 1;
    }

    function getRefund() public {
        uint refunds = 0;
        for (uint i = 1; i <= totalTickets; i++) {
            if (msg.sender == contestants[i].addr && raffleId == contestants[i].raffleId) {
                refunds++;
                contestants[i] = Contestant(address(0), 0);
                gaps.push(i);
            }
        }

        if (refunds > 0) {
            msg.sender.transfer(refunds * pricePerTicket);
        }
    }

    function kill() public {
        if (msg.sender == creatorAddress) {
            selfdestruct(creatorAddress);
        }
    }
}