/*
 * ===== SmartInject Injection Details =====
 * Function      : claimBonus
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability in bonus claiming system. Users must first call accumulateBonus() multiple times over different time periods to build up their bonus balance, then call claimBonus() to withdraw. The claimBonus() function is vulnerable to reentrancy because it makes an external call before updating the accumulatedBonus state, allowing malicious contracts to recursively call claimBonus() and drain accumulated bonuses from multiple time periods.
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
    
    mapping (address => User) private users;
    Entry[] private entries;
    uint[] private unpaidEntries;

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint) bonusClaimTime;
    mapping (address => uint) accumulatedBonus;
    mapping (address => bool) bonusClaimInProgress;
    
    function accumulateBonus() public {
        require(users[msg.sender].id != address(0), "User not registered");
        require(users[msg.sender].deposits > 0, "No deposits found");
        
        uint timeSinceLastClaim = now - bonusClaimTime[msg.sender];
        if (timeSinceLastClaim >= 1 hours) {
            uint bonusAmount = (users[msg.sender].deposits * 5 finney) / 100;
            accumulatedBonus[msg.sender] += bonusAmount;
            bonusClaimTime[msg.sender] = now;
        }
    }
    
    function claimBonus() public {
        require(users[msg.sender].id != address(0), "User not registered");
        require(accumulatedBonus[msg.sender] > 0, "No bonus to claim");
        require(!bonusClaimInProgress[msg.sender], "Claim in progress");
        
        bonusClaimInProgress[msg.sender] = true;
        
        uint bonusAmount = accumulatedBonus[msg.sender];
        
        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(bonusAmount)()) {
            // State update happens after external call
            accumulatedBonus[msg.sender] = 0;
            bonusClaimInProgress[msg.sender] = false;
        } else {
            bonusClaimInProgress[msg.sender] = false;
        }
    }
    
    function getBonusStatus(address user) public view returns (uint accumulated, uint nextClaimTime) {
        accumulated = accumulatedBonus[user];
        nextClaimTime = bonusClaimTime[user] + 1 hours;
    }
    // === END FALLBACK INJECTION ===

    //Set owner on contract creation
    function KeberuntunganAcak() {
        owner = msg.sender;
    }

    modifier onlyowner { if (msg.sender == owner) _ ;}
    
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
        
        //Add new entry to the entries array
        entries.push(Entry(msg.sender, dValue, (dValue * (multiplier) / 100), false));
        users[msg.sender].deposits++;
        unpaidEntries.push(entries.length -1);
        
        //Collect fees and update contract balance
        balance += (dValue * (100 - fee)) / 100;
        
        uint index = unpaidEntries.length > 1 ? rand(unpaidEntries.length) : 0;
        Entry theEntry = entries[unpaidEntries[index]];
        
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
