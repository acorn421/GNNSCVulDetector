/*
 * ===== SmartInject Injection Details =====
 * Function      : PlayNow
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a consecutive wins tracking system. The vulnerability requires: 1) Initial transactions to accumulate consecutive wins state, 2) A winning transaction that triggers the external call before state cleanup, 3) Reentrancy exploitation during the external call to manipulate the persistent consecutiveWins mapping. The attacker must build up consecutive wins over multiple transactions, then exploit the reentrancy window to prevent the consecutive wins counter from being reset, allowing for inflated bonus multipliers in subsequent plays.
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




contract WorldLotteryFast is owned {
    uint public countTickets = 4;
    uint public JackPot = 10000000000000000;
    address[100] public tickets;
    uint public ticketPrice = 10000000000000000;                         
    uint public toJackPotfromEveryTicket = 1000000000000000;
    uint public lastWinNumber;
    uint public ticketCounter;
    bool public playFast = true;

    // ===== ADDED: Variable to fix undeclared variable errors =====
    mapping(address => uint) public consecutiveWins;
	
    /* This generates a public event on the blockchain that will notify clients */
	event Transfer(address indexed from, address indexed to, uint256 value);

    function clearTickets() public {
        for (uint i = 0 ; i < countTickets ; i++ )
            tickets[i] = 0;
    }

    
	function PlayNow() public returns (bool success)  {     
        lastWinNumber = uint(block.blockhash(block.number-1))%countTickets + 1;                                  // take random number
        
		if (tickets[lastWinNumber] != 0 ) {  
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			// Progressive jackpot feature: track consecutive wins for bonus multiplier
			consecutiveWins[msg.sender]++;
			
			// Calculate bonus multiplier based on consecutive wins
			uint bonusMultiplier = 1;
			if (consecutiveWins[msg.sender] >= 3) {
				bonusMultiplier = 2;
			}
			if (consecutiveWins[msg.sender] >= 5) {
				bonusMultiplier = 3;
			}
			
			uint totalPayout = JackPot * bonusMultiplier;
			
			// External call before state cleanup - vulnerable to reentrancy
			msg.sender.transfer(totalPayout);
			Transfer(this, msg.sender, totalPayout);
			
			// State cleanup happens after external call - vulnerable window
			JackPot = 0;
			consecutiveWins[msg.sender] = 0;  // Reset consecutive wins after payout
        } else {
			// Reset consecutive wins if no win
			consecutiveWins[msg.sender] = 0;
		}
        
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        JackPot += toJackPotfromEveryTicket;                                					            // send tokens to JackPot
        tickets[ticketId] = msg.sender;                                 					           // write senders address to ticketlist
       
        Transfer(msg.sender,this,ticketPrice);
        
		if (playFast)                                                           					                          //if fast play
		    PlayNow();
		else{
		    ticketCounter++;                                                    					                 //if need to buy all tickets
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
