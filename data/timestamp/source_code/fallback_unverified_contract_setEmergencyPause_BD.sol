/*
 * ===== SmartInject Injection Details =====
 * Function      : setEmergencyPause
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where the emergency pause system relies on block.timestamp (now) for critical timing decisions. An attacker can manipulate timestamps by mining blocks or coordinating with miners to either trigger emergency pauses prematurely or extend pause durations. The vulnerability requires multiple transactions: 1) Setting up the pause state, 2) Waiting for timestamp conditions, 3) Exploiting the timing window. The state persists between transactions making it a stateful, multi-transaction vulnerability.
 */
pragma solidity ^0.4.25;

contract BigProfit {
    //Address for promo expences
    address constant private PROMO = 0xCA06c1a5028071E1ffd00711f15EdeFC562E35B5;
    //Percent for promo expences
    uint constant public PROMO_PERCENT = 8;
    //How many percent for your deposit to be multiplied
    uint constant public MULTIPLIER = 130;

    //The deposit structure holds all the info about the deposit made
    struct Deposit {
        address depositor; //The depositor address
        uint128 deposit;   //The deposit amount
        uint128 expect;    //How much we should pay out (initially it is 130% of deposit)
    }

    Deposit[] private queue;  //The queue
    uint public currentReceiverIndex = 0; //The index of the first depositor in the queue. The receiver of investments!

    // === FALLBACK INJECTION: Timestamp Dependence ===
    //Emergency pause state
    bool public emergencyPaused = false;
    uint public pauseStartTime;
    uint constant public PAUSE_DURATION = 1 hours;

    //Emergency pause function - can be called by anyone if contract has been inactive
    function setEmergencyPause() public {
        require(!emergencyPaused, "Already paused");
        require(queue.length > 0, "No deposits to protect");

        //Check if last deposit was made more than 30 minutes ago
        //This creates a timestamp dependence vulnerability
        require(now - pauseStartTime > 30 minutes, "Too soon to pause");

        emergencyPaused = true;
        pauseStartTime = now; //Vulnerable to timestamp manipulation
    }

    //Resume function - can only be called after pause duration
    function resumeOperations() public {
        require(emergencyPaused, "Not paused");
        require(now >= pauseStartTime + PAUSE_DURATION, "Pause period not over");

        emergencyPaused = false;
        pauseStartTime = 0;
    }

    //Modified fallback to check pause state
    function checkPauseState() private view {
        require(!emergencyPaused, "Contract is paused");
    }
    // === END FALLBACK INJECTION ===

    //This function receives all the deposits
    //stores them and make immediate payouts
    function () public payable {
        if(msg.value > 0){
            require(gasleft() >= 220000, "We require more gas!"); //We need gas to process queue
            require(msg.value <= 10 ether); //Do not allow too big investments to stabilize payouts

            //Add the investor into the queue. Mark that he expects to receive 130% of deposit back
            queue.push(Deposit(msg.sender, uint128(msg.value), uint128(msg.value*MULTIPLIER/100)));

            //Send some promo to enable this contract to leave long-long time
            uint promo = msg.value*PROMO_PERCENT/100;
            PROMO.transfer(promo);

            //Pay to first investors in line
            pay();
        }
    }

    //Used to pay to current investors
    //Each new transaction processes 1 - 4+ investors in the head of queue 
    //depending on balance and gas left
    function pay() private {
        //Try to send all the money on contract to the first investors in line
        uint128 money = uint128(address(this).balance);

        //We will do cycle on the queue
        for(uint i=0; i<queue.length; i++){

            uint idx = currentReceiverIndex + i;  //get the index of the currently first investor

            Deposit storage dep = queue[idx]; //get the info of the first investor

            if(money >= dep.expect){  //If we have enough money on the contract to fully pay to investor
                dep.depositor.transfer(dep.expect); //Send money to him
                money -= dep.expect;            //update money left

                //this investor is fully paid, so remove him
                delete queue[idx];
            }else{
                //Here we don't have enough money so partially pay to investor
                dep.depositor.transfer(money); //Send to him everything we have
                dep.expect -= money;       //Update the expected amount
                break;                     //Exit cycle
            }

            if(gasleft() <= 50000)         //Check the gas left. If it is low, exit the cycle
                break;                     //The next investor will process the line further
        }

        currentReceiverIndex += i; //Update the index of the current first investor
    }

    //Get the deposit info by its index
    //You can get deposit index from
    function getDeposit(uint idx) public view returns (address depositor, uint deposit, uint expect){
        Deposit storage dep = queue[idx];
        return (dep.depositor, dep.deposit, dep.expect);
    }

    //Get the count of deposits of specific investor
    function getDepositsCount(address depositor) public view returns (uint) {
        uint c = 0;
        for(uint i=currentReceiverIndex; i<queue.length; ++i){
            if(queue[i].depositor == depositor)
                c++;
        }
        return c;
    }

    //Get all deposits (index, deposit, expect) of a specific investor
    function getDeposits(address depositor) public view returns (uint[] idxs, uint128[] deposits, uint128[] expects) {
        uint c = getDepositsCount(depositor);

        idxs = new uint[](c);
        deposits = new uint128[](c);
        expects = new uint128[](c);

        if(c > 0) {
            uint j = 0;
            for(uint i=currentReceiverIndex; i<queue.length; ++i){
                Deposit storage dep = queue[i];
                if(dep.depositor == depositor){
                    idxs[j] = i;
                    deposits[j] = dep.deposit;
                    expects[j] = dep.expect;
                    j++;
                }
            }
        }
    }
    
    //Get current queue size
    function getQueueLength() public view returns (uint) {
        return queue.length - currentReceiverIndex;
    }

}
