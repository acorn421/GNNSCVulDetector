/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This introduces a multi-transaction reentrancy vulnerability where an attacker must: 1) Get admin approval via enableEmergencyWithdraw(), 2) Call requestEmergencyWithdraw() to set up pending withdrawal state, 3) Call emergencyWithdraw() which makes external call before updating state, allowing reentrancy to drain more funds than entitled. The vulnerability requires state persistence across multiple transactions and cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.25;

contract EtherwaterTest {
    //Address for promo expences
    address constant private PROMO = 0x014bF153476683dC0A0673325C07EB3342281DC8;
    //Percent for promo expences
    uint constant public PROMO_PERCENT = 6; //6 for advertizing, 1 for techsupport
    //How many percent for your deposit to be multiplied
    uint constant public MULTIPLIER = 119;

    //The deposit structure holds all the info about the deposit made
    struct Deposit {
        address depositor; //The depositor address
        uint128 deposit;   //The deposit amount
        uint128 expect;    //How much we should pay out (initially it is 121% of deposit)
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public emergencyWithdrawEnabled;
    uint256 public emergencyWithdrawDelay = 24 hours;
    
    // Admin function to enable emergency withdrawals for specific users
    function enableEmergencyWithdraw(address user) public {
        require(msg.sender == PROMO, "Only admin can enable emergency withdrawals");
        emergencyWithdrawEnabled[user] = true;
    }
    
    // First step: Request emergency withdrawal (requires admin approval first)
    function requestEmergencyWithdraw() public {
        require(emergencyWithdrawEnabled[msg.sender], "Emergency withdraw not enabled for user");
        
        // Calculate user's total expected returns from their deposits
        uint256 totalExpected = 0;
        for(uint i = currentReceiverIndex; i < queue.length; i++) {
            if(queue[i].depositor == msg.sender) {
                totalExpected += queue[i].expect;
            }
        }
        
        require(totalExpected > 0, "No deposits found");
        pendingWithdrawals[msg.sender] = totalExpected;
    }
    
    // Second step: Execute emergency withdrawal (vulnerable to reentrancy)
    function emergencyWithdraw() public {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        
        uint256 amount = pendingWithdrawals[msg.sender];
        require(address(this).balance >= amount, "Insufficient contract balance");
        
        // VULNERABILITY: External call before state update
        // This allows reentrancy attacks across multiple transactions
        msg.sender.call.value(amount)("");
        
        // State update happens after external call - vulnerable to reentrancy
        pendingWithdrawals[msg.sender] = 0;
        
        // Remove user's deposits from queue
        for(uint i = currentReceiverIndex; i < queue.length; i++) {
            if(queue[i].depositor == msg.sender) {
                delete queue[i];
            }
        }
    }
    // === END FALLBACK INJECTION ===

    Deposit[] private queue;  //The queue
    uint public currentReceiverIndex = 0; //The index of the first depositor in the queue. The receiver of investments!

    //This function receives all the deposits
    //stores them and make immediate payouts
    function () public payable {
        if(msg.value > 0){
            require(gasleft() >= 220000, "We require more gas!"); //We need gas to process queue
            require(msg.value <= 13 ether); //Do not allow too big investments to stabilize payouts

            //Add the investor into the queue. Mark that he expects to receive 121% of deposit back
            queue.push(Deposit(msg.sender, uint128(msg.value), uint128(msg.value*MULTIPLIER/100)));

            //Send some promo to enable this contract to leave long-long time
            uint promo = msg.value*PROMO_PERCENT/100;
            PROMO.send(promo);

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
                dep.depositor.send(dep.expect); //Send money to him
                money -= dep.expect;            //update money left

                //this investor is fully paid, so remove him
                delete queue[idx];
            }else{
                //Here we don't have enough money so partially pay to investor
                dep.depositor.send(money); //Send to him everything we have
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
    function getSingleDeposit(uint idx) public view returns (address depositor, uint deposit, uint expect){
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
    function getAllDeposits(address depositor) public view returns (uint[] idxs, uint128[] deposits, uint128[] expects) {
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
