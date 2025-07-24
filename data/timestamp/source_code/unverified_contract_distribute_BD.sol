/*
 * ===== SmartInject Injection Details =====
 * Function      : distribute
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a sophisticated timestamp dependence vulnerability that creates a multi-transaction exploit opportunity. The vulnerability is injected by adding time-based distribution bonuses and penalties that can be manipulated across multiple transactions.
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added Timestamp State Variables**: The function now uses `lastDistributionTime`, `distributionWindowStart`, and `consecutiveDistributions` to track timing patterns across multiple calls.
 * 
 * 2. **Time-Based Bonus System**: 
 *    - Quick consecutive distributions (within 1 hour) receive a 1.2x bonus
 *    - Delayed distributions (over 1 day) receive a 0.8x penalty
 *    - Sustained frequent distributions (5+ consecutive) receive a 1.5x bonus
 * 
 * 3. **Applied to All Distribution Phases**: The time-based multiplier affects percentage-based distributions, even distributions, and remainder distributions.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Phase 1 - Setup (Transaction 1)**: An attacker calls `distribute()` for the first time, establishing `lastDistributionTime` and beginning the tracking system.
 * 
 * **Phase 2 - Accumulation (Transactions 2-4)**: The attacker makes 4 more calls to `distribute()` within 1-hour windows, each time receiving the 1.2x bonus and incrementing `consecutiveDistributions`.
 * 
 * **Phase 3 - Exploitation (Transaction 5+)**: On the 5th consecutive call within the timing window, the attacker triggers the maximum 1.5x bonus, extracting significantly more funds than intended.
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The `consecutiveDistributions` counter must be built up over multiple calls to reach the maximum bonus threshold.
 * 
 * 2. **Timing Dependencies**: The vulnerability relies on the time elapsed between calls, which can only be measured across multiple transactions.
 * 
 * 3. **Miner Manipulation**: Miners can potentially manipulate `block.timestamp` to extend the timing windows, but this requires coordination across multiple blocks/transactions.
 * 
 * **Realistic Attack Scenario:**
 * 
 * A malicious miner or someone with influence over mining pools could:
 * 1. Control the timing of transactions in blocks they mine
 * 2. Manipulate `block.timestamp` within acceptable ranges (typically 15 seconds forward)
 * 3. Coordinate multiple `distribute()` calls to maximize bonuses
 * 4. Extract up to 50% more funds than intended through the timing manipulation
 * 
 * This vulnerability is particularly dangerous because it appears to be a legitimate "efficiency incentive" feature while actually creating an exploitable timing dependency that rewards those who can manipulate transaction timing.
 */
pragma solidity ^0.4.6;

// --------------------------
//  R Split Contract
// --------------------------
contract RSPLT_I {
        event StatEvent(string msg);
        event StatEventI(string msg, uint val);

        enum SettingStateValue  {debug, locked}

        struct partnerAccount {
                uint credited;  // total funds credited to this account
                uint balance;   // current balance = credited - amount withdrawn
                uint pctx10;     // percent allocation times ten
                address addr;   // payout addr of this acct
                bool evenStart; // even split up to evenDistThresh
        }

// -----------------------------
//  data storage
// ----------------------------------------
        address public owner;                                // deployer executor
        mapping (uint => partnerAccount) partnerAccounts;    // accounts by index
        uint public numAccounts;                             // how many accounts exist
        uint public holdoverBalance;                         // amount yet to be distributed
        uint public totalFundsReceived;                      // amount received since begin of time
        uint public totalFundsDistributed;                   // amount distributed since begin of time
        uint public totalFundsWithdrawn;                     // amount withdrawn since begin of time
        uint public evenDistThresh;                          // distribute evenly until this amount (total)
        uint public withdrawGas = 35000;                     // gas for withdrawals
        uint constant TENHUNDWEI = 1000;                     // need gt. 1000 wei to do payout
        uint constant MAX_ACCOUNTS = 5;                      // max accounts this contract can handle
        SettingStateValue public settingsState = SettingStateValue.debug;

        // --- Variables for injected vulnerability ---
        uint public lastDistributionTime;
        uint public distributionWindowStart;
        uint public consecutiveDistributions;
        // ---------------------------------------

        // --------------------
        // contract constructor
        // --------------------
        function RSPLT_I() {
                owner = msg.sender;
        }


        // -----------------------------------
        // lock
        // lock the contract. after calling this you will not be able to modify accounts.
        // make sure everyhting is right!
        // -----------------------------------
        function lock() {
                if (msg.sender != owner) {
                        StatEvent("err: not owner");
                        return;
                }
                if (settingsState == SettingStateValue.locked) {
                        StatEvent("err: locked");
                        return;
                }
                settingsState = SettingStateValue.locked;
                StatEvent("ok: contract locked");
        }


        // -----------------------------------
        // reset
        // reset all accounts
        // in case we have any funds that have not been withdrawn, they become
        // newly received and undistributed.
        // -----------------------------------
        function reset() {
                if (msg.sender != owner) {
                        StatEvent("err: not owner");
                        return;
                }
                if (settingsState == SettingStateValue.locked) {
                        StatEvent("err: locked");
                        return;
                }
                for (uint i = 0; i < numAccounts; i++ ) {
                        holdoverBalance += partnerAccounts[i].balance;
                }
                totalFundsReceived = holdoverBalance;
                totalFundsDistributed = 0;
                totalFundsWithdrawn = 0;
                numAccounts = 0;
                StatEvent("ok: all accts reset");
        }


        // -----------------------------------
        // set even distribution threshold
        // -----------------------------------
        function setEvenDistThresh(uint256 _thresh) {
                if (msg.sender != owner) {
                        StatEvent("err: not owner");
                        return;
                }
                if (settingsState == SettingStateValue.locked) {
                        StatEvent("err: locked");
                        return;
                }
                evenDistThresh = (_thresh / TENHUNDWEI) * TENHUNDWEI;
                StatEventI("ok: threshold set", evenDistThresh);
        }


        // -----------------------------------
        // set even distribution threshold
        // -----------------------------------
        function setWitdrawGas(uint256 _withdrawGas) {
                if (msg.sender != owner) {
                        StatEvent("err: not owner");
                        return;
                }
                withdrawGas = _withdrawGas;
                StatEventI("ok: withdraw gas set", withdrawGas);
        }


        // ---------------------------------------------------
        // add a new account
        // ---------------------------------------------------
        function addAccount(address _addr, uint256 _pctx10, bool _evenStart) {
                if (msg.sender != owner) {
                        StatEvent("err: not owner");
                        return;
                }
                if (settingsState == SettingStateValue.locked) {
                        StatEvent("err: locked");
                        return;
                }
                if (numAccounts >= MAX_ACCOUNTS) {
                        StatEvent("err: max accounts");
                        return;
                }
                partnerAccounts[numAccounts].addr = _addr;
                partnerAccounts[numAccounts].pctx10 = _pctx10;
                partnerAccounts[numAccounts].evenStart = _evenStart;
                partnerAccounts[numAccounts].credited = 0;
                partnerAccounts[numAccounts].balance = 0;
                ++numAccounts;
                StatEvent("ok: acct added");
        }


        // ----------------------------
        // get acct info
        // ----------------------------
        function getAccountInfo(address _addr) constant returns(uint _idx, uint _pctx10, bool _evenStart, uint _credited, uint _balance) {
                for (uint i = 0; i < numAccounts; i++ ) {
                        address addr = partnerAccounts[i].addr;
                        if (addr == _addr) {
                                _idx = i;
                                _pctx10 = partnerAccounts[i].pctx10;
                                _evenStart = partnerAccounts[i].evenStart;
                                _credited = partnerAccounts[i].credited;
                                _balance = partnerAccounts[i].balance;
                                StatEvent("ok: found acct");
                                return;
                        }
                }
                StatEvent("err: acct not found");
        }


        // ----------------------------
        // get total percentages x10
        // ----------------------------
        function getTotalPctx10() constant returns(uint _totalPctx10) {
                _totalPctx10 = 0;
                for (uint i = 0; i < numAccounts; i++ ) {
                        _totalPctx10 += partnerAccounts[i].pctx10;
                }
                StatEventI("ok: total pctx10", _totalPctx10);
        }


        // ----------------------------
        // get no. accts that are set for even split
        // ----------------------------
        function getNumEvenSplits() constant returns(uint _numEvenSplits) {
                _numEvenSplits = 0;
                for (uint i = 0; i < numAccounts; i++ ) {
                        if (partnerAccounts[i].evenStart) {
                                ++_numEvenSplits;
                        }
                }
                StatEventI("ok: even splits", _numEvenSplits);
        }


        // -------------------------------------------
        // default payable function.
        // call us with plenty of gas, or catastrophe will ensue
        // note: you can call this fcn with amount of zero to force distribution
        // -------------------------------------------
        function () payable {
                totalFundsReceived += msg.value;
                holdoverBalance += msg.value;
                StatEventI("ok: incoming", msg.value);
        }


        // ----------------------------
        // distribute funds to all partners
        // ----------------------------
        function distribute() {
                //only payout if we have more than 1000 wei
                if (holdoverBalance < TENHUNDWEI) {
                        return;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Initialize or check distribution timestamp window
                if (lastDistributionTime == 0) {
                        lastDistributionTime = block.timestamp;
                        distributionWindowStart = block.timestamp;
                }
                
                // Calculate time-based distribution bonus/penalty
                uint timeBonusMultiplier = TENHUNDWEI; // default 1x multiplier
                uint timeSinceLastDist = block.timestamp - lastDistributionTime;
                
                // Bonus for quick consecutive distributions (within 1 hour)
                if (timeSinceLastDist < 3600) {
                        timeBonusMultiplier = 1200; // 1.2x bonus
                        consecutiveDistributions++;
                } else if (timeSinceLastDist > 86400) {
                        // Penalty for delayed distributions (more than 1 day)
                        timeBonusMultiplier = 800; // 0.8x penalty
                        consecutiveDistributions = 0;
                }
                
                // Extra bonus for sustained frequent distributions
                if (consecutiveDistributions >= 5) {
                        timeBonusMultiplier = 1500; // 1.5x bonus
                }
                
                lastDistributionTime = block.timestamp;
                
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                //first pay accounts that are not constrained by even distribution
                //each account gets their prescribed percentage of this holdover.
                uint i;
                uint pctx10;
                uint acctDist;
                uint maxAcctDist;
                uint numEvenSplits = 0;
                for (i = 0; i < numAccounts; i++ ) {
                        if (partnerAccounts[i].evenStart) {
                                ++numEvenSplits;
                        } else {
                                pctx10 = partnerAccounts[i].pctx10;
                                acctDist = holdoverBalance * pctx10 / TENHUNDWEI;
                                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                                
                                // Apply time-based bonus/penalty
                                acctDist = acctDist * timeBonusMultiplier / TENHUNDWEI;
                                
                                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                                //we also double check to ensure that the amount awarded cannot exceed the
                                //total amount due to this acct. note: this check is necessary, cuz here we
                                //might not distribute the full holdover amount during each pass.
                                maxAcctDist = totalFundsReceived * pctx10 / TENHUNDWEI;
                                if (partnerAccounts[i].credited >= maxAcctDist) {
                                        acctDist = 0;
                                } else if (partnerAccounts[i].credited + acctDist > maxAcctDist) {
                                        acctDist = maxAcctDist - partnerAccounts[i].credited;
                                }
                                partnerAccounts[i].credited += acctDist;
                                partnerAccounts[i].balance += acctDist;
                                totalFundsDistributed += acctDist;
                                holdoverBalance -= acctDist;
                        }
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                //now pay accounts that are constrained by even distribution. we split whatever is
                //left of the holdover evenly.
                uint distAmount = holdoverBalance;
                if (totalFundsDistributed < evenDistThresh) {
                        for (i = 0; i < numAccounts; i++ ) {
                                if (partnerAccounts[i].evenStart) {
                                        acctDist = distAmount / numEvenSplits;
                                        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                                        
                                        // Apply time-based bonus/penalty to even distribution accounts too
                                        acctDist = acctDist * timeBonusMultiplier / TENHUNDWEI;
                                        
                                        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                                        //we also double check to ensure that the amount awarded cannot exceed the
                                        //total amount due to this acct. note: this check is necessary, cuz here we
                                        //might not distribute the full holdover amount during each pass.
                                        uint fundLimit = totalFundsReceived;
                                        if (fundLimit > evenDistThresh)
                                                fundLimit = evenDistThresh;
                                        maxAcctDist = fundLimit / numEvenSplits;
                                        if (partnerAccounts[i].credited >= maxAcctDist) {
                                                acctDist = 0;
                                        } else if (partnerAccounts[i].credited + acctDist > maxAcctDist) {
                                                acctDist = maxAcctDist - partnerAccounts[i].credited;
                                        }
                                        partnerAccounts[i].credited += acctDist;
                                        partnerAccounts[i].balance += acctDist;
                                        totalFundsDistributed += acctDist;
                                        holdoverBalance -= acctDist;
                                }
                        }
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                //now, if there are any funds left then it means that we have either exceeded the even distribution threshold,
                //or there is a remainder in the even split. in that case distribute all the remmaing funds to partners who have
                //not yet exceeded their allotment, according to their "effective" percentages. note that this must be done here,
                //even if we haven't passed the even distribution threshold, to ensure that we don't get stuck with a remainder
                //amount that cannot be distributed.
                distAmount = holdoverBalance;
                if (distAmount > 0) {
                        uint totalDistPctx10 = 0;
                        for (i = 0; i < numAccounts; i++ ) {
                                pctx10 = partnerAccounts[i].pctx10;
                                maxAcctDist = totalFundsReceived * pctx10 / TENHUNDWEI;
                                if (partnerAccounts[i].credited < maxAcctDist) {
                                        totalDistPctx10 += pctx10;
                                }
                        }
                        for (i = 0; i < numAccounts; i++ ) {
                                pctx10 = partnerAccounts[i].pctx10;
                                acctDist = distAmount * pctx10 / totalDistPctx10;
                                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                                
                                // Apply time-based bonus/penalty to remainder distribution
                                acctDist = acctDist * timeBonusMultiplier / TENHUNDWEI;
                                
                                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                                //we also double check to ensure that the amount awarded cannot exceed the
                                //total amount due to this acct. note: this check is necessary, cuz here we
                                //might not distribute the full holdover amount during each pass.
                                maxAcctDist = totalFundsReceived * pctx10 / TENHUNDWEI;
                                if (partnerAccounts[i].credited >= maxAcctDist) {
                                        acctDist = 0;
                                } else if (partnerAccounts[i].credited + acctDist > maxAcctDist) {
                                        acctDist = maxAcctDist - partnerAccounts[i].credited;
                                }
                                partnerAccounts[i].credited += acctDist;
                                partnerAccounts[i].balance += acctDist;
                                totalFundsDistributed += acctDist;
                                holdoverBalance -= acctDist;
                        }
                }
                StatEvent("ok: distributed funds");
        }


        // ----------------------------
        // withdraw account balance
        // ----------------------------
        function withdraw() {
                for (uint i = 0; i < numAccounts; i++ ) {
                        address addr = partnerAccounts[i].addr;
                        if (addr == msg.sender || msg.sender == owner) {
                                uint amount = partnerAccounts[i].balance;
                                if (amount == 0) { 
                                        StatEvent("err: balance is zero");
                                } else {
                                        partnerAccounts[i].balance = 0;
                                        totalFundsWithdrawn += amount;
                                        if (!addr.call.gas(withdrawGas).value(amount)())
                                                revert();
                                        StatEventI("ok: rewards paid", amount);
                                }
                        }
                }
        }


        // ----------------------------
        // suicide
        // ----------------------------
        function hariKari() {
                if (msg.sender != owner) {
                        StatEvent("err: not owner");
                        return;
                }
                if (settingsState == SettingStateValue.locked) {
                        StatEvent("err: locked");
                        return;
                }
                suicide(owner);
        }

}
