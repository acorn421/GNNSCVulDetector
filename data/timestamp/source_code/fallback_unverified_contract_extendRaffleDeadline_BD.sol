/*
 * ===== SmartInject Injection Details =====
 * Function      : extendRaffleDeadline
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that is stateful and requires multiple transactions to exploit. The vulnerability allows malicious miners to manipulate block timestamps across multiple transactions to repeatedly extend raffle deadlines. The exploit requires: 1) First transaction to call initializeRaffleDeadline(), 2) Multiple transactions calling requestExtension() near the deadline with manipulated timestamps, 3) State persistence through raffleDeadline and extensionRequests variables. This creates a multi-transaction attack vector where miners can prevent raffles from completing by continuously extending deadlines through timestamp manipulation.
 */
pragma solidity ^0.4.0;

contract Ethraffle {
    // Structs
    struct Contestant {
        address addr;
        uint raffleId;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for deadline extension functionality
    uint public raffleDeadline = 0;
    uint public extensionRequests = 0;
    uint constant public maxExtensions = 3;
    uint constant public extensionDuration = 1 hours;
    
    // Initialize deadline when raffle starts
    function initializeRaffleDeadline() public {
        require(raffleDeadline == 0 || block.timestamp > raffleDeadline);
        raffleDeadline = block.timestamp + 24 hours;
        extensionRequests = 0;
    }
    
    // Allow participants to request deadline extension
    function requestExtension() public {
        require(extensionRequests < maxExtensions, "Maximum extensions reached");
        require(block.timestamp >= raffleDeadline - 2 hours, "Too early to request extension");
        require(nextTicket <= totalTickets, "Raffle already completed");
        
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        // Multi-transaction exploit: Miner can manipulate timestamp across multiple blocks
        // to repeatedly extend deadline and prevent raffle completion
        if (block.timestamp >= raffleDeadline - 1 hours) {
            raffleDeadline = block.timestamp + extensionDuration;
            extensionRequests++;
        }
    }
    
    // Force raffle completion if deadline passed
    function forceRaffleCompletion() public {
        require(block.timestamp > raffleDeadline + 1 hours, "Deadline not exceeded");
        require(nextTicket > 1, "No tickets sold");
        
        // Vulnerable: Timestamp dependence allows manipulation
        // If fewer than total tickets sold, choose winner from available tickets
        if (nextTicket <= totalTickets) {
            chooseWinner();
        }
    }
    // === END FALLBACK INJECTION ===

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
