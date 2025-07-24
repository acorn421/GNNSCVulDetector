/*
 * ===== SmartInject Injection Details =====
 * Function      : join
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Timestamp Storage**: Modified the Entry struct to store `block.timestamp` for each entry, creating persistent state that accumulates across transactions.
 * 
 * 2. **Time-based Bonus System**: Added logic that gives bonus multipliers (150% instead of 125%) to users who join within 1 hour of the previous entry. This creates a timing-dependent payout calculation that persists in contract state.
 * 
 * 3. **Priority Payout Selection**: Implemented a system where entries older than 10 minutes get priority for payouts over random selection. This creates time-dependent behavior that changes based on accumulated timestamps from previous transactions.
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker joins to establish a timestamp baseline
 * - **Transaction 2**: Attacker waits and monitors for optimal timing windows (within 1 hour for bonus, after 10 minutes for priority)
 * - **Transaction 3+**: Attacker exploits by timing subsequent entries to maximize bonus multipliers and payout priority
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires timestamp accumulation across multiple entries stored in contract state
 * - Bonus calculations depend on time differences between current and previous entries
 * - Priority payout selection requires entries to "age" in the unpaid queue for at least 10 minutes
 * - Miners can manipulate timestamps across multiple blocks to influence both bonus eligibility and payout selection
 * 
 * **Realistic Attack Vector:**
 * A miner could manipulate block timestamps across multiple transactions to:
 * 1. Ensure their entries always qualify for the 1-hour bonus window
 * 2. Manipulate the aging of entries to guarantee priority payout selection
 * 3. Coordinate timing to maximize their expected returns while minimizing others' chances
 * 
 * The vulnerability is subtle and appears to be a legitimate "feature" for encouraging timely participation, making it realistic for production code.
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
    function KeberuntunganAcak() public {
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
        uint timestamp;
    }

    //Fallback function
    function() public payable {
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        //Time-locked entry system with bonus multiplier
        uint entryTimestamp = block.timestamp;
        uint bonusMultiplier = multiplier;
        
        //Users who join within 1 hour of the last entry get bonus payout
        if (entries.length > 0) {
            uint lastEntryTime = entries[entries.length - 1].timestamp;
            if (entryTimestamp - lastEntryTime <= 3600) {
                bonusMultiplier = multiplier + 25; // 150% instead of 125%
            }
        }
        
        //Add new entry to the entries array with timestamp
        entries.push(Entry(msg.sender, dValue, (dValue * bonusMultiplier / 100), false, entryTimestamp));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        users[msg.sender].deposits++;
        unpaidEntries.push(entries.length -1);
        
        //Collect fees and update contract balance
        balance += (dValue * (100 - fee)) / 100;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        //Time-based payout selection - entries older than 10 minutes get priority
        uint index = 0;
        if (unpaidEntries.length > 1) {
            bool foundOldEntry = false;
            for (uint i = 0; i < unpaidEntries.length; i++) {
                Entry storage oldEntry = entries[unpaidEntries[i]];
                if (entryTimestamp - oldEntry.timestamp >= 600) { // 10 minutes
                    index = i;
                    foundOldEntry = true;
                    break;
                }
            }
            if (!foundOldEntry) {
                index = rand(unpaidEntries.length);
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Entry storage theEntry = entries[unpaidEntries[index]];
        
        //Pay pending entries if the new balance allows for it
        if (balance > theEntry.payout) {
            
            uint payout = theEntry.payout;
            
            (theEntry.entryAddress.send(payout));
            theEntry.paid = true;
            users[theEntry.entryAddress].payoutsReceived++;

            balance -= payout;
            
            if (index < unpaidEntries.length - 1)
                unpaidEntries[index] = unpaidEntries[unpaidEntries.length - 1];
           
            unpaidEntries.length--;
            
        }
        
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
        if (multi < 110 || multi > 150) revert();
        
        multiplier = multi;
    }
    
    function changeFee(uint newFee) onlyowner private {
        if (fee > 2) 
            revert();
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
