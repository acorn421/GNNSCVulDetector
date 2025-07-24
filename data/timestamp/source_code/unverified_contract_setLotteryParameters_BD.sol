/*
 * ===== SmartInject Injection Details =====
 * Function      : setLotteryParameters
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that requires the addition of new state variables (lastParameterUpdateTime, parameterUpdateCount, dailyBonusActive, bonusMultiplier) to the contract. The vulnerability creates a time-based parameter update system where:
 * 
 * 1. **State Persistence**: The function stores timestamp-dependent state (lastParameterUpdateTime, parameterUpdateCount, dailyBonusActive, bonusMultiplier) that persists between transactions and influences future parameter updates.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Owner calls setLotteryParameters, establishing initial timestamp-dependent state
 *    - **Transaction 2+**: Subsequent calls compound the effects based on block.timestamp differences
 *    - **Exploitation Phase**: Miners can manipulate block timestamps across multiple transactions to:
 *      - Artificially increase jackpot multipliers by manipulating time differences
 *      - Trigger daily bonus periods by setting timestamps to specific time windows
 *      - Accumulate parameter update counts to compound jackpot increases
 * 
 * 3. **Timestamp Dependence Elements**:
 *    - Uses `block.timestamp` for critical jackpot calculations
 *    - Implements time-based multipliers that compound across multiple updates
 *    - Creates daily bonus windows vulnerable to timestamp manipulation
 *    - Stores time-dependent state that affects future calculations
 * 
 * 4. **Realistic Vulnerability**: The code appears to implement a legitimate time-based bonus system for lottery parameters, but the reliance on block.timestamp for financial calculations creates an exploitable vulnerability that requires multiple transactions to fully exploit.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires building up state through multiple parameter updates, with each update compounding the timestamp-dependent effects.
 */
pragma solidity ^0.4.2;
contract owned {
    address public owner;

    function owned() public {
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
    
    // === Added missing state variables for setLotteryParameters ===
    uint public lastParameterUpdateTime;
    uint public parameterUpdateCount;
    bool public dailyBonusActive;
    uint public bonusMultiplier;

    /* This generates a public event on the blockchain that will notify clients */
	event Transfer(address indexed from, address indexed to, uint256 value);

    function clearTickets() public {
        for (uint i = 0 ; i < countTickets ; i++ )
            tickets[i] = 0;
    }

    
	function PlayNow() public returns (bool success)  {     
        lastWinNumber = uint(block.blockhash(block.number-1))%countTickets + 1;                                  // take random number
            
		if (tickets[lastWinNumber] !=0 ){  
			msg.sender.transfer(JackPot);
			Transfer(this,msg.sender,JackPot);                                             //send Jack Pot to the winner
			JackPot = 0;                                                                                                                               // and clear JackPot
        }  
        clearTickets();
        
        return true;
    }
    
    
	function getJackPot() public returns (uint jPot)  {     
        return JackPot;
    }
	
 
    function setLotteryParameters(uint newCountTickets, uint newTicketPrice, uint newToJackPotfromEveryTicket, uint newJackPot, bool newPlayFast) public onlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based parameter update system with cumulative effects
        uint currentTime = block.timestamp;
        
        // Store the timestamp when parameters were last updated
        if (lastParameterUpdateTime == 0) {
            lastParameterUpdateTime = currentTime;
        }
        
        // Calculate time-based multiplier for jackpot increases
        uint timeDiff = currentTime - lastParameterUpdateTime;
        uint jackpotMultiplier = 1 + (timeDiff / 3600); // Increases every hour
        
        // Apply cumulative time-based effects
        countTickets = newCountTickets;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        ticketPrice = newTicketPrice;
        toJackPotfromEveryTicket = newToJackPotfromEveryTicket;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable: Jackpot calculation depends on block.timestamp
        // and accumulates effects from multiple parameter updates
        if (parameterUpdateCount == 0) {
            JackPot = newJackPot;
        } else {
            // Each subsequent update compounds the jackpot based on timestamp
            JackPot = newJackPot * jackpotMultiplier;
        }
        
        playFast = newPlayFast;
        
        // Update state variables for multi-transaction exploitation
        lastParameterUpdateTime = currentTime;
        parameterUpdateCount++;
        
        // Time-based bonus multiplier that persists across transactions
        if (currentTime % 86400 < 3600) { // First hour of each day
            dailyBonusActive = true;
            bonusMultiplier = 2;
        } else if (dailyBonusActive && currentTime % 86400 > 3600) {
            // Bonus remains active but can be exploited through timestamp manipulation
            bonusMultiplier = 1;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
  
    
}

contract PlayLottery is WorldLotteryFast{


function adopt(uint ticketId) public payable returns (uint) {
        
		require(msg.value>=ticketPrice);

		require(ticketId >= 0 && ticketId <= countTickets);
		
		if ( tickets[ticketId] != 0x0000000000000000000000000000000000000000 ) return 0;                                             // Check if ticket already buyed
        JackPot += toJackPotfromEveryTicket;                                                                                       // send tokens to JackPot
        tickets[ticketId] = msg.sender;                                                                                            // write senders address to ticketlist
       
        Transfer(msg.sender,this,ticketPrice);
        
		if (playFast)                                                                                                               //if fast play
		    PlayNow();
		else{
		    ticketCounter++;                                                                                                         //if need to buy all tickets
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
