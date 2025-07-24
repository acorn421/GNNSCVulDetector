/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawDeposit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This function introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires multiple transactions to set up: 1) First, an attacker needs to make a deposit to get into the queue, 2) Then call withdrawDeposit multiple times to manipulate the withdrawalAttempts mapping through reentrancy, 3) The state changes persist between transactions allowing the attacker to accumulate withdrawal attempts and potentially withdraw more than intended. The vulnerability is in the external call happening before all state cleanup is complete, and the withdrawal tracking state persists between transactions.
 */
pragma solidity ^0.4.25;

/**
  Multiplier ETHMOON: returns 125% of each investment!
  Fully transparent smartcontract with automatic payments proven professionals.
  An additional level of protection against fraud - you can make only two deposits, until you get 125%.

  [.... docstring elided for brevity ....]
*/

contract Ethmoon {
    // address for promo expences
    address constant private PROMO = 0xa4Db4f62314Db6539B60F0e1CBE2377b918953Bd;
    address constant private TECH = 0x093D552Bde4D55D2e32dedA3a04D3B2ceA2B5595;
    // percent for promo/tech expences
    uint constant public PROMO_PERCENT = 6;
    uint constant public TECH_PERCENT = 2;
    // how many percent for your deposit to be multiplied
    uint constant public MULTIPLIER = 125;
    // deposit limits
    uint constant public MIN_DEPOSIT = .01 ether;
    uint constant public MAX_DEPOSIT = 5 ether;

    // the deposit structure holds all the info about the deposit made
    struct Deposit {
        address depositor; // the depositor address
        uint128 deposit;   // the deposit amount
        uint128 expect;    // how much we should pay out (initially it is 125% of deposit)
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // withdrawal tracker to manage withdrawal limits
    mapping(address => uint) public withdrawalAttempts;
    mapping(address => uint) public lastWithdrawalTime;

    // allows users to withdraw their deposit before it's paid out (with penalty)
    function withdrawDeposit(uint depositIndex) public {
        require(depositIndex >= currentReceiverIndex, "Deposit already processed");
        require(depositIndex < queue.length, "Invalid deposit index");
        Deposit storage dep = queue[depositIndex];
        require(dep.depositor == msg.sender, "Not your deposit");
        require(dep.expect > 0, "Deposit already withdrawn");
        // Track withdrawal attempts to prevent spam
        withdrawalAttempts[msg.sender]++;
        lastWithdrawalTime[msg.sender] = now;
        // Calculate penalty (10% of original deposit)
        uint penalty = dep.deposit * 10 / 100;
        uint withdrawAmount = dep.deposit - penalty;
        // Update state before external call (but vulnerability exists in multi-step process)
        dep.expect = 0;
        // VULNERABILITY: External call before all state changes are complete
        // This creates a reentrancy window where attacker can manipulate withdrawal tracking
        if (withdrawAmount > 0) {
            msg.sender.call.value(withdrawAmount)("");
        }
        // State changes after external call - this is where the vulnerability lies
        // An attacker can reenter and modify withdrawalAttempts before this cleanup
        if (withdrawalAttempts[msg.sender] > 1) {
            withdrawalAttempts[msg.sender] = 1; // Reset attempts after successful withdrawal
        }
    }
    // === END FALLBACK INJECTION ===

    Deposit[] private queue;  // the queue
    uint public currentReceiverIndex = 0; // the index of the first depositor in the queue. The receiver of investments!

    // this function receives all the deposits
    // stores them and make immediate payouts
    function () public payable {
        require(gasleft() >= 220000, "We require more gas!"); // we need gas to process queue
        require((msg.value >= MIN_DEPOSIT) && (msg.value <= MAX_DEPOSIT)); // do not allow too big investments to stabilize payouts
        require(getDepositsCount(msg.sender) < 2); // not allow more than 2 deposit in until you to receive 125% of deposit back
        // add the investor into the queue. Mark that he expects to receive 125% of deposit back
        queue.push(Deposit(msg.sender, uint128(msg.value), uint128(msg.value * MULTIPLIER/100)));
        // send some promo to enable this contract to leave long-long time
        uint promo = msg.value * PROMO_PERCENT/100;
        PROMO.transfer(promo);
        uint tech = msg.value * TECH_PERCENT/100;
        TECH.transfer(tech);
        // pay to first investors in line
        pay();
    }

    // used to pay to current investors
    // each new transaction processes 1 - 4+ investors in the head of queue 
    // depending on balance and gas left
    function pay() private {
        // try to send all the money on contract to the first investors in line
        uint128 money = uint128(address(this).balance);
        // we will do cycle on the queue
        uint i;
        for (i = 0; i < queue.length - currentReceiverIndex; i++) {
            uint idx = currentReceiverIndex + i;  // get the index of the currently first investor
            Deposit storage dep = queue[idx]; // get the info of the first investor
            if (money >= dep.expect) {  // if we have enough money on the contract to fully pay to investor
                dep.depositor.transfer(dep.expect); // send money to him
                money -= dep.expect;            // update money left
                // this investor is fully paid, so remove him
                delete queue[idx];
            } else {
                // here we don't have enough money so partially pay to investor
                dep.depositor.transfer(money); // send to him everything we have
                dep.expect -= money;       // update the expected amount
                break;                     // exit cycle
            }
            if (gasleft() <= 50000)         // check the gas left. If it is low, exit the cycle
                break;                     // the next investor will process the line further
        }
        currentReceiverIndex += i; // update the index of the current first investor
    }

    // get the deposit info by its index
    // you can get deposit index from
    function getDeposit(uint idx) public view returns (address depositor, uint deposit, uint expect){
        Deposit storage dep = queue[idx];
        return (dep.depositor, dep.deposit, dep.expect);
    }

    // get the count of deposits of specific investor
    function getDepositsCount(address depositor) public view returns (uint) {
        uint c = 0;
        for (uint i=currentReceiverIndex; i<queue.length; ++i) {
            if(queue[i].depositor == depositor)
                c++;
        }
        return c;
    }

    // get all deposits (index, deposit, expect) of a specific investor
    function getDeposits(address depositor) public view returns (uint[] idxs, uint128[] deposits, uint128[] expects) {
        uint c = getDepositsCount(depositor);
        idxs = new uint[](c);
        deposits = new uint128[](c);
        expects = new uint128[](c);
        if (c > 0) {
            uint j = 0;
            for (uint i=currentReceiverIndex; i<queue.length; ++i) {
                Deposit storage dep = queue[i];
                if (dep.depositor == depositor) {
                    idxs[j] = i;
                    deposits[j] = dep.deposit;
                    expects[j] = dep.expect;
                    j++;
                }
            }
        }
    }
    // get current queue size
    function getQueueLength() public view returns (uint) {
        return queue.length - currentReceiverIndex;
    }
}
