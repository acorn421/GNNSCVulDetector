/*
 * ===== SmartInject Injection Details =====
 * Function      : getRefund
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Separated state checking from state updates**: Split the original loop into two separate loops - one for counting refunds and another for clearing state
 * 2. **External call before state updates**: Moved the external call (using call.value()) to occur BEFORE the state clearing loop, violating the Checks-Effects-Interactions pattern
 * 3. **Used call.value() instead of transfer()**: Replaced the safer transfer() with call.value() which allows for reentrancy and provides more gas to the called contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker purchases multiple tickets across different transactions to accumulate contestant entries
 * - Each ticket purchase creates persistent state in the contestants mapping with the current raffleId
 * 
 * **Transaction 2 (Exploitation)**:
 * - Attacker calls getRefund() from a malicious contract
 * - The function counts refunds but doesn't clear contestant state yet
 * - External call triggers attacker's fallback function
 * - Attacker reenters getRefund() multiple times before state is cleared
 * - Each reentrant call sees the same uncleaned contestant state and processes the same refunds
 * - After all reentrant calls complete, the state clearing loop finally executes
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior state accumulation (buying tickets) in separate transactions
 * - The contestant entries must exist in persistent storage before the reentrancy exploitation
 * - The raffleId-based validation ensures the attack works across transaction boundaries
 * - Single transaction exploitation is not possible because you need pre-existing ticket purchases to have refundable entries
 * 
 * **Realistic Exploitation Impact:**
 * - Attacker can drain multiple times the legitimate refund amount
 * - The persistent state (contestants mapping, gaps array) enables repeated exploitation
 * - The vulnerability leverages the contract's intended multi-transaction usage pattern (buy tickets, then get refunds)
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
    constructor() public {
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
        return (uint(keccak256(
          abi.encodePacked(
            block.timestamp,
            block.number,
            block.gaslimit,
            block.difficulty,
            msg.gas,
            uint(msg.sender),
            uint(block.coinbase)
          )
        )) % totalTickets) + 1;
    }

    function getRefund() public {
        uint refunds = 0;
        uint i;
        for (i = 1; i <= totalTickets; i++) {
            if (msg.sender == contestants[i].addr && raffleId == contestants[i].raffleId) {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                refunds++;
            }
        }

        if (refunds > 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call BEFORE state updates - enables reentrancy
            msg.sender.call.value(refunds * pricePerTicket)("");
            
            // State updates happen AFTER external call - vulnerable to reentrancy
            for (i = 1; i <= totalTickets; i++) {
                if (msg.sender == contestants[i].addr && raffleId == contestants[i].raffleId) {
                    contestants[i] = Contestant(address(0), 0);
                    gaps.push(i);
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }

    function kill() public {
        if (msg.sender == creatorAddress) {
            selfdestruct(creatorAddress);
        }
    }
}
