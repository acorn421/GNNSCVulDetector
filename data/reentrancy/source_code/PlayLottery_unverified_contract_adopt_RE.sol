/*
 * ===== SmartInject Injection Details =====
 * Function      : adopt
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call (transfer for overpayment refund) before state updates. This creates a classic reentrancy attack surface where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker needs multiple transactions to:
 *    - First, build up the JackPot through legitimate adopt() calls
 *    - Deploy a malicious contract that can receive transfers
 *    - Execute the exploit transaction with overpayment to trigger the vulnerable external call
 * 
 * 2. **State Accumulation Dependency**: The vulnerability becomes more valuable as the JackPot grows through multiple adopt() calls across different transactions. The attacker needs to wait for or contribute to this state accumulation.
 * 
 * 3. **Reentrancy Exploitation**: When the malicious contract receives the overpayment refund, it can re-enter the adopt() function before the state variables (JackPot, tickets, ticketCounter) are fully updated, allowing:
 *    - Multiple ticket purchases with the same funds
 *    - Manipulation of the lottery state
 *    - Potential draining of accumulated JackPot funds
 * 
 * 4. **Realistic Attack Scenario**: The attacker must:
 *    - Transaction 1-N: Make legitimate adopt() calls to build up JackPot
 *    - Transaction N+1: Call adopt() with overpayment from malicious contract
 *    - During the refund transfer, re-enter adopt() multiple times before state is updated
 *    - Potentially trigger PlayNow() with manipulated state
 * 
 * This vulnerability requires careful orchestration across multiple transactions and depends on the accumulated state from previous legitimate transactions, making it a genuine stateful, multi-transaction reentrancy attack.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerability: Add external call before state updates
        // Send refund for overpayment before updating state
        if (msg.value > ticketPrice) {
            msg.sender.transfer(msg.value - ticketPrice);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        JackPot += toJackPotfromEveryTicket;                                			    								            // send tokens to JackPot
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