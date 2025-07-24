/*
 * ===== SmartInject Injection Details =====
 * Function      : adopt
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through time-based JackPot contribution calculations. The vulnerability involves:
 * 
 * 1. **Timestamp-Based Bonus System**: Uses block.timestamp % 300 == 0 to determine when to double contributions, creating predictable timing windows that miners can manipulate.
 * 
 * 2. **Stored Timestamp Logic**: Stores block.timestamp in a local variable and uses it for multiple calculations, allowing for timing-dependent state changes.
 * 
 * 3. **Accumulated State Exploitation**: The vulnerability depends on ticketCounter state that accumulates across transactions, combined with timestamp calculations that create exploitable timing windows.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls adopt() to increment ticketCounter and establish timing baseline
 *    - **Wait Period**: Attacker waits for favorable timestamp conditions (when block.timestamp % 300 == 0 or other timing conditions align)
 *    - **Transaction 2**: Attacker calls adopt() again when timing conditions are met to receive massive JackPot bonuses
 * 
 * 5. **Miner Manipulation Potential**: Miners can manipulate block timestamps within reasonable bounds (±15 seconds) to:
 *    - Ensure block.timestamp % 300 == 0 for double contributions
 *    - Align timing calculations for the complex bonus condition
 *    - Exploit the predictable timing windows for maximum JackPot contribution
 * 
 * The vulnerability is realistic because timestamp-based bonuses are common in lottery systems, but the predictable nature and miner manipulation potential create a serious security flaw that requires multiple transactions and accumulated state to exploit effectively.
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
			Transfer(this,msg.sender,JackPot);												//send Jack Pot to the winner
			JackPot = 0;                                                                	                                                                // and clear JackPot
        }  
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
		
		if ( tickets[ticketId] != 0x0000000000000000000000000000000000000000 ) return 0;                        		    // Check if ticket already buyed
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent JackPot contribution with accumulating state
        uint timeBasedContribution = toJackPotfromEveryTicket;
        
        // Add time-based bonus that accumulates over multiple transactions
        if (block.timestamp % 300 == 0) {  // Every 5 minutes exact
            timeBasedContribution = timeBasedContribution * 2;  // Double contribution
        }
        
        // Store timestamp for later use in critical operations
        uint storedTimestamp = block.timestamp;
        
        // Vulnerable: Use stored timestamp for determining special conditions
        if (storedTimestamp % 100 < 10) {  // 10% chance based on timestamp
            // Grant special privileges that persist across transactions
            timeBasedContribution = timeBasedContribution * 3;  // Triple contribution
            
            // Manipulable timing condition affects subsequent state
            if (ticketCounter > 0 && (storedTimestamp - (ticketCounter * 60)) % 120 == 0) {
                // Predictable timing window - can be exploited by miners
                JackPot += timeBasedContribution * 5;  // Massive bonus
            }
        }
        
        JackPot += timeBasedContribution;                                			    								            // send tokens to JackPot
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        tickets[ticketId] = msg.sender;                                    	    											           // write senders address to ticketlist
       
        Transfer(msg.sender,this,ticketPrice);
        
		if (playFast)                                                           											                          //if fast play
		    PlayNow();
		else{
		    ticketCounter++;                                                    											                 //if need to buy all tickets
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