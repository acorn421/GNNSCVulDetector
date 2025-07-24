/*
 * ===== SmartInject Injection Details =====
 * Function      : PlayNow
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple function calls to exploit:
 * 
 * 1. **Time-Based Bonus Accumulation**: Added logic that increases the jackpot based on time elapsed between plays, stored in `lastPlayTime` state variable. This creates a multi-transaction vulnerability where attackers can manipulate timestamps across multiple blocks to accelerate bonus accumulation.
 * 
 * 2. **Lucky Hour Restrictions**: Implemented time-window logic that only allows immediate payouts during "lucky hours" (8 PM to 11 PM). Winners outside these hours are stored as pending winners who must claim later during lucky hours.
 * 
 * 3. **Timestamp-Influenced Randomness**: Enhanced the random number generation to include `block.timestamp`, making the lottery outcome partially dependent on block timing that miners can influence.
 * 
 * 4. **Pending Winner System**: Added state variables (`pendingWinner`, `pendingWinTime`, `pendingAmount`) that persist winner information across transactions, creating a multi-transaction exploitation pathway.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Bonus Accumulation Attack**: 
 *    - Transaction 1: Call PlayNow() to establish `lastPlayTime`
 *    - Miner manipulates timestamps in subsequent blocks
 *    - Transaction 2+: Call PlayNow() with inflated time differences to accumulate larger bonuses
 * 
 * 2. **Lucky Hour Manipulation**:
 *    - Transaction 1: Win lottery outside lucky hours (becomes pending winner)
 *    - Miner manipulates timestamps to create artificial "lucky hour" periods
 *    - Transaction 2: Call PlayNow() or claim during manipulated lucky hours
 * 
 * 3. **Cross-Block Timing Attack**:
 *    - Multiple transactions across different blocks where miners coordinate timestamp manipulation
 *    - Each transaction builds upon the previous state to maximize payout timing
 * 
 * The vulnerability requires persistent state changes between transactions and cannot be exploited atomically within a single transaction, making it a genuine multi-transaction timestamp dependence vulnerability.
 */
pragma solidity ^0.4.2;
contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}




contract WorldLotteryFast is owned{
    uint public countTickets = 4;
    uint public JackPot = 10000000000000000;
    address[100] public tickets;
    uint public ticketPrice = 10000000000000000;                         
    uint public toJackPotfromEveryTicket = 1000000000000000;
    uint public lastWinNumber;
    uint public ticketCounter;
    bool public playFast=true;
    
    // Added missing variables
    uint public lastPlayTime;
    address public pendingWinner;
    uint public pendingWinTime;
    uint public pendingAmount;
 
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    function clearTickets() public {
        for (uint i = 0 ; i < countTickets ; i++ )
            tickets[i] = address(0);
    }

    
    function PlayNow() public returns (bool success)  {     
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store current timestamp for time-based bonus calculation
        uint currentTime = block.timestamp;
        
        // Calculate time-based jackpot multiplier (bonus accumulates over time)
        uint timeBonus = 0;
        if (lastPlayTime > 0) {
            uint timeDiff = currentTime - lastPlayTime;
            timeBonus = (timeDiff * JackPot) / 86400; // 1% of jackpot per day
            JackPot += timeBonus;
        }
        
        // Use timestamp-influenced randomness for winner selection
        lastWinNumber = uint(keccak256(abi.encodePacked(block.blockhash(block.number-1), currentTime)))%countTickets + 1;
        
        // Time-window restriction: only allow play during "lucky hours" (predictable for miners)
        uint hourOfDay = (currentTime / 3600) % 24;
        bool isLuckyHour = (hourOfDay >= 20 && hourOfDay <= 23); // 8 PM to 11 PM
        
        if (tickets[lastWinNumber] != address(0) && isLuckyHour) {
            // Additional timestamp-based bonus for lucky hour winners
            uint luckyBonus = (currentTime % 100) * 1000000000000000; // Varies by timestamp
            uint totalPayout = JackPot + luckyBonus;
            
            msg.sender.transfer(totalPayout);
            Transfer(this, msg.sender, totalPayout);
            JackPot = 0;
        } else if (tickets[lastWinNumber] != address(0) && !isLuckyHour) {
            // Store pending winner for later claim during lucky hours
            pendingWinner = msg.sender;
            pendingWinTime = currentTime;
            pendingAmount = JackPot;
            // Don't transfer yet - winner must claim during lucky hours
        }
        
        // Update last play time for next bonus calculation
        lastPlayTime = currentTime;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        clearTickets();
        
        return true;
    }
    
    
    function getJackPot() public returns (uint jPot)  {     
        return JackPot;
    }
 
    function setLotteryParameters(uint newCountTickets, uint newTicketPrice, uint newToJackPotfromEveryTicket, uint newJackPot, bool newPlayFast) public onlyOwner {
        countTickets=newCountTickets;
        ticketPrice = newTicketPrice;
        toJackPotfromEveryTicket = newToJackPotfromEveryTicket;
        JackPot=newJackPot;
        playFast=newPlayFast;
    }
  
    
}

contract PlayLottery is WorldLotteryFast{


function adopt(uint ticketId) public payable returns (uint) {
        
        require(msg.value>=ticketPrice);

        require(ticketId >= 0 && ticketId <= countTickets);
        
        if ( tickets[ticketId] != 0x0000000000000000000000000000000000000000 ) return 0;                                                        // Check if ticket already buyed
        JackPot += toJackPotfromEveryTicket;                                                                                                       // send tokens to JackPot
        tickets[ticketId] = msg.sender;                                                                                                           // write senders address to ticketlist
       
        Transfer(msg.sender,this,ticketPrice);
        
        if (playFast)                                                                                                                            //if fast play
            PlayNow();
        else{
            ticketCounter++;                                                                                                     //if need to buy all tickets
            if (ticketCounter==countTickets)
                PlayNow();
        }
        
       
        return ticketId;
}


// Retrieving the adopters
function getAdopters() public view returns (address[100]) {
  return tickets;
}

function withdraw() public onlyOwner {
        owner.transfer(this.balance);
}


function killMe() public onlyOwner {
        selfdestruct(owner);
}

function getLastWinNumber() public returns (uint){
        return lastWinNumber;
}

function getTicket(uint newTicketId) public returns (address){
        return  tickets[newTicketId];
}

}
