/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTickets
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables** (assume these exist in contract):
 *    - `mapping(address => bool) public processingRefund` - tracks addresses currently processing refunds
 *    - `mapping(address => uint) public refundAmount` - stores pending refund amounts
 * 
 * 2. **Modified External Call Pattern**:
 *    - Replaced `msg.sender.transfer(moneySent)` with `msg.sender.call.value(moneySent)()`
 *    - Added state tracking before the external call (`processingRefund[msg.sender] = true`)
 *    - Set refund amount in state before the call
 * 
 * 3. **Multi-Transaction Exploitation Mechanism**:
 *    - **Transaction 1**: Attacker calls `buyTickets()` with excess funds, triggers the refund mechanism which sets `processingRefund[attacker] = true` and `refundAmount[attacker] = X`
 *    - **Transaction 2**: During the `.call()` callback, attacker's contract can call `buyTickets()` again, and the persistent state from Transaction 1 (`processingRefund[attacker] = true`) can be exploited
 *    - **Subsequent Transactions**: The attacker can manipulate the raffle state by leveraging the persistent `processingRefund` and `refundAmount` mappings across multiple calls
 * 
 * 4. **Stateful Vulnerability**:
 *    - The vulnerability requires the `processingRefund` mapping to be set to `true` in a previous transaction
 *    - Attackers can use this persistent state to bypass normal flow controls in subsequent transactions
 *    - The `refundAmount` mapping persists between transactions, allowing accumulated exploitation
 * 
 * 5. **Exploitation Scenario**:
 *    - Attacker deploys a malicious contract with a fallback function
 *    - Calls `buyTickets()` with excess funds to trigger refund flow
 *    - During the `.call()` callback, the malicious contract can call `buyTickets()` again
 *    - The persistent state allows the attacker to manipulate ticket allocation or extract additional funds across multiple transactions
 *    - Each transaction builds upon the state changes from previous transactions
 * 
 * This vulnerability is realistic because it mimics real-world patterns where contracts use callback mechanisms for payment processing and maintain state across transactions.
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
    // Added missing state variables for refund tracking
    mapping(address => bool) public processingRefund;
    mapping(address => uint) public refundAmount;

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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Send back leftover money with callback mechanism
        if (moneySent > 0) {
            // Mark as processing refund to enable callback
            processingRefund[msg.sender] = true;
            refundAmount[msg.sender] = moneySent;
            
            // External call that can trigger reentrancy
            if (!msg.sender.call.value(moneySent)()) {
                // If call fails, revert refund state
                processingRefund[msg.sender] = false;
                refundAmount[msg.sender] = 0;
            }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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