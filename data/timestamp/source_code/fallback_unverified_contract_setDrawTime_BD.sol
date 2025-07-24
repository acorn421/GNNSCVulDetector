/*
 * ===== SmartInject Injection Details =====
 * Function      : setDrawTime
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
 * Timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps to control when lottery draws occur. First transaction sets up the draw time, subsequent transactions can manipulate the timestamp, and final transaction executes the draw at an advantageous time. The state persists between transactions through the nextDrawTime variable.
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
			Transfer(this,msg.sender,JackPot);                                                //send Jack Pot to the winner
			JackPot = 0;                                                                  // and clear JackPot
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
		
		if ( tickets[ticketId] != 0x0000000000000000000000000000000000000000 ) return 0;                          // Check if ticket already buyed
        JackPot += toJackPotfromEveryTicket;                                 // send tokens to JackPot
        tickets[ticketId] = msg.sender;                                     // write senders address to ticketlist
       
        Transfer(msg.sender,this,ticketPrice);
        
		if (playFast)                                                           //if fast play
		    PlayNow();
		else{
		    ticketCounter++;                                                    //if need to buy all tickets
		    if (ticketCounter==countTickets)
		        PlayNow();
		}
		
       
		return ticketId;
}

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public nextDrawTime;
    uint public drawDelay = 3600; // 1 hour default

    function setDrawTime(uint delaySeconds) public onlyOwner {
        nextDrawTime = now + delaySeconds;
    }

    function scheduleTimedDraw() public {
        if (nextDrawTime == 0 || now >= nextDrawTime) {
            nextDrawTime = now + drawDelay;
            // Allow immediate draw if no time was set or time has passed
            if (ticketCounter >= countTickets / 2) {
                PlayNow();
            }
        }
    }

    function executeTimedDraw() public returns (bool) {
        require(nextDrawTime > 0);
        require(now >= nextDrawTime);
        
        // Vulnerability: miners can manipulate timestamp to trigger draws early
        // This creates a multi-transaction attack where:
        // 1. Attacker buys tickets
        // 2. Attacker (if miner) manipulates timestamp in subsequent blocks
        // 3. Attacker calls executeTimedDraw() to trigger draw at advantageous time
        
        PlayNow();
        nextDrawTime = 0;
        return true;
    }
    // === END FALLBACK INJECTION ===


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
