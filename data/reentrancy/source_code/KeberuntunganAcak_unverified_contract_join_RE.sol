/*
 * ===== SmartInject Injection Details =====
 * Function      : join
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering operations to place the external call (theEntry.entryAddress.send(payout)) before critical state updates. The vulnerability requires multiple transactions to build up exploitable state:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. **Moved balance update**: The `balance += (dValue * (100 - fee)) / 100` is now executed AFTER the payout logic instead of before
 * 2. **External call before state updates**: The `(theEntry.entryAddress.send(payout))` now occurs before `theEntry.paid = true`, `users[theEntry.entryAddress].payoutsReceived++`, and `balance -= payout`
 * 3. **Reordered entry creation**: Entry creation happens before balance checks to enable state manipulation
 * 
 * **MULTI-TRANSACTION EXPLOITATION PATTERN:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1-N (State Building Phase):**
 * - Attacker calls join() multiple times to accumulate entries in unpaidEntries array
 * - Each call adds entry but doesn't trigger payout due to insufficient balance
 * - Attacker builds up multiple pending entries in the system
 * 
 * **Transaction N+1 (Trigger Phase):**
 * - Enough balance accumulates to trigger a payout to one of attacker's entries
 * - When `theEntry.entryAddress.send(payout)` is called, attacker's contract receives control
 * - Since state updates haven't occurred yet, attacker can re-enter join() while:
 *   - `theEntry.paid` is still false
 *   - `balance` hasn't been decremented yet
 *   - `unpaidEntries` array hasn't been updated
 * 
 * **Reentrancy Attack:**
 * - During the send() callback, attacker re-enters join()
 * - The reentrant call sees the old state where balance appears higher than it should be
 * - This allows attacker to trigger additional payouts or manipulate the unpaidEntries array
 * - Attacker can repeatedly drain the contract by exploiting the inconsistent state
 * 
 * **WHY MULTI-TRANSACTION IS REQUIRED:**
 * 1. **State Accumulation**: Attacker must first build up multiple entries across several transactions
 * 2. **Balance Threshold**: Contract needs sufficient balance from other users to trigger payouts
 * 3. **Timing Dependencies**: The vulnerability only becomes exploitable when specific state conditions are met across multiple transactions
 * 4. **Persistent State Corruption**: Each successful reentrancy attack corrupts the state in ways that enable future exploitation
 * 
 * This creates a realistic vulnerability where the attacker must strategically participate in the lottery system over multiple transactions to create the necessary conditions for exploitation.
 */
pragma solidity ^0.4.8;
contract KeberuntunganAcak {
//##########################################################
//##Payout ialah acak dan tidak mengikut antrian####
//##Keacakan berdasarkan random hashblock oleh miner####
//#### Deposit 0.05 ETHER + fee gas utk partisipasi ####
//#### 2% dari 0.05 Ether akan diperuntukkan utk fee kepada owner ####
//#### Jika transfer lebih dari 0.05Ether maka sisanya akan dikembalikan ####
//###Jika beruntung maka bisa lgs dapat payout##########
//###Jika gak beruntung maka harus wait ##########
//###payout ialah 125% ##########
//###payout ialah otomatis dan contract tidak dapat dimodif lagi setelah deploy oleh sesiapapun termasuk owner ##########
//COPYRIGHT 2017 hadioneyesoneno
//Edukasi dan eksperimen purpose only


    address private owner;
    
    //Stored variables
    uint private balance = 0;
    uint private fee = 2;
    uint private multiplier = 125;

    mapping (address => User) private users;
    Entry[] private entries;
    uint[] private unpaidEntries;
    
    //Set owner on contract creation
    function KeberuntunganAcak() {
        owner = msg.sender;
    }

    modifier onlyowner { if (msg.sender == owner) _ ;}
    
    struct User {
        address id;
        uint deposits;
        uint payoutsReceived;
    }
    
    struct Entry {
        address entryAddress;
        uint deposit;
        uint payout;
        bool paid;
    }

    //Fallback function
    function() {
        init();
    }
    
    function init() private{
        
        if (msg.value < 50 finney) {
             (msg.sender.send(msg.value));
            return;
        }
        
        join();
    }
    
    function join() public payable {
        
        //Limit deposits to 0.05ETH
        uint dValue = 50 finney;
        
        if (msg.value > 50 finney) {
            
        	(msg.sender.send(msg.value - 50 finney));	
        	dValue = 50 finney;
        }
      
        //Add new users to the users array
        if (users[msg.sender].id == address(0))
        {
            users[msg.sender].id = msg.sender;
            users[msg.sender].deposits = 0;
            users[msg.sender].payoutsReceived = 0;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        //Add new entry to the entries array - moved before balance update to enable reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        entries.push(Entry(msg.sender, dValue, (dValue * (multiplier) / 100), false));
        users[msg.sender].deposits++;
        unpaidEntries.push(entries.length -1);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        uint index = unpaidEntries.length > 1 ? rand(unpaidEntries.length) : 0;
        Entry theEntry = entries[unpaidEntries[index]];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        //Pay pending entries if the new balance allows for it - external call before state updates
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (balance > theEntry.payout) {
            
            uint payout = theEntry.payout;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: External call before state updates - enables reentrancy
            (theEntry.entryAddress.send(payout));
            
            // State updates after external call - can be manipulated through reentrancy
            theEntry.paid = true;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            users[theEntry.entryAddress].payoutsReceived++;
            balance -= payout;
            
            if (index < unpaidEntries.length - 1)
                unpaidEntries[index] = unpaidEntries[unpaidEntries.length - 1];
           
            unpaidEntries.length--;
            
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        //Collect fees and update contract balance - moved after payout logic
        balance += (dValue * (100 - fee)) / 100;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        //Collect money from fees and possible leftovers from errors (actual balance untouched)
        uint fees = this.balance - balance;
        if (fees > 0)
        {
                (owner.send(fees));
        }      
       
    }
    
    //Generate random number between 0 & max
    uint256 constant private FACTOR =  1157920892373161954235709850086879078532699846656405640394575840079131296399;
    function rand(uint max) constant private returns (uint256 result){
        uint256 factor = FACTOR * 100 / max;
        uint256 lastBlockNumber = block.number - 1;
        uint256 hashVal = uint256(block.blockhash(lastBlockNumber));
    
        return uint256((uint256(hashVal) / factor)) % max;
    }
    
    
    //Contract management
    function changeOwner(address newOwner) onlyowner private {
        owner = newOwner;
    }
    
    function changeMultiplier(uint multi) onlyowner private {
        if (multi < 110 || multi > 150) throw;
        
        multiplier = multi;
    }
    
    function changeFee(uint newFee) onlyowner private {
        if (fee > 2) 
            throw;
        fee = newFee;
    }
    
    
    //JSON functions
    function multiplierFactor() constant returns (uint factor, string info) {
        factor = multiplier;
        info = 'multipliyer ialah 125%'; 
    }
    
    function currentFee() constant returns (uint feePercentage, string info) {
        feePercentage = fee;
        info = 'fee ialah 2%.';
    }
    
    function totalEntries() constant returns (uint count, string info) {
        count = entries.length;
        info = 'seberapa banyak deposit';
    }
    
    function userStats(address user) constant returns (uint deposits, uint payouts, string info)
    {
        if (users[user].id != address(0x0))
        {
            deposits = users[user].deposits;
            payouts = users[user].payoutsReceived;
            info = 'Users stats: total deposits, payouts diterima.';
        }
    }
    
    function entryDetails(uint index) constant returns (address user, uint payout, bool paid, string info)
    {
        if (index < entries.length) {
            user = entries[index].entryAddress;
            payout = entries[index].payout / 1 finney;
            paid = entries[index].paid;
            info = 'Entry info: user address, expected payout in Finneys, payout status.';
        }
    }
    
    
}