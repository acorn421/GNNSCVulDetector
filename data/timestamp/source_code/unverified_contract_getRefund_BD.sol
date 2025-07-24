/*
 * ===== SmartInject Injection Details =====
 * Function      : getRefund
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
 * Injected a timestamp dependence vulnerability by using block.timestamp for refund amount calculation with a time-based multiplier. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **State Persistence**: The function stores timestamp information in the contestants mapping using a hash-based key, creating persistent state between transactions.
 * 
 * 2. **Multi-Transaction Exploitation**: An attacker can:
 *    - Transaction 1: Call getRefund() when timestamp conditions are unfavorable (low multiplier)
 *    - Transaction 2+: Wait for favorable timestamp values and call again, potentially getting higher multipliers based on block.timestamp manipulation
 * 
 * 3. **Timestamp Manipulation**: The vulnerability uses `block.timestamp % 1000` to create a multiplier (1-11x), which miners can influence by manipulating block timestamps within the allowed ~15 second drift.
 * 
 * 4. **Cumulative Effect**: Each call modifies state (contestants mapping) and the timestamp-based calculations compound over multiple transactions, making timing manipulation profitable across multiple blocks.
 * 
 * The vulnerability is realistic because refund mechanisms often have time-based components, and the code appears to implement a "late refund bonus" that could be business logic gone wrong.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        uint currentTime = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint i = 1; i <= totalTickets; i++) {
            if (msg.sender == contestants[i].addr && raffleId == contestants[i].raffleId) {
                refunds++;
                contestants[i] = Contestant(address(0), 0);
                gaps.push(i);
            }
        }

        if (refunds > 0) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Time-based refund calculation - refund amount increases over time
            uint timeMultiplier = 1 + ((currentTime % 1000) / 100); // 1-11x multiplier based on timestamp
            uint refundAmount = refunds * pricePerTicket * timeMultiplier;
            
            // Store the timestamp when refund is calculated for future reference
            uint timestampKey = uint(keccak256(abi.encodePacked(msg.sender, raffleId))) % 100;
            contestants[timestampKey] = Contestant(msg.sender, currentTime);
            
            msg.sender.transfer(refundAmount);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }

    function kill() public {
        if (msg.sender == creatorAddress) {
            selfdestruct(creatorAddress);
        }
    }
}