/*
 * ===== SmartInject Injection Details =====
 * Function      : setLotteryParameters
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external contract calls before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Setup Phase (Transaction 1)**: Owner calls setLotteryParameters() with new values
 * 2. **Exploitation Window**: External calls to partnerNotificationContract and configChangeCallback occur before state updates
 * 3. **Reentrancy Attack (During callbacks)**: Malicious contracts can call back into the lottery contract while old parameter values are still active
 * 4. **State Persistence**: The vulnerability persists across multiple transactions because:
 *    - Old parameter values remain active during the external call window
 *    - Attackers can purchase tickets at old prices while new jackpot values are being set
 *    - Multiple adopt() calls can be made during the callback window
 * 5. **Completion (Original transaction finishes)**: New parameter values finally take effect
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single atomic transaction
 * - Requires the owner to call setLotteryParameters() first (Transaction 1)
 * - Exploitation happens during the callback window when external contracts are called
 * - Attackers need separate transactions to interact with adopt() function during callbacks
 * - The attack window persists until the original setLotteryParameters() transaction completes
 * 
 * **Exploitation Scenario:**
 * 1. Owner calls setLotteryParameters() to increase jackpot from 1 ETH to 10 ETH
 * 2. External notification calls trigger, creating reentrancy window
 * 3. Malicious callback contract calls adopt() multiple times at old ticket prices
 * 4. Attacker accumulates tickets cheaply while new higher jackpot is about to be set
 * 5. When original transaction completes, attacker has tickets bought at old prices but eligible for new jackpot
 * 
 * This creates a realistic vulnerability where parameter changes can be exploited across multiple transactions through callback mechanisms.
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

// Interface declarations for external calls
interface IPartnerNotification {
    function notifyParameterChange(uint countTickets, uint ticketPrice, uint toJackPotfromEveryTicket, uint JackPot, bool playFast) external;
}

interface IConfigCallback {
    function onConfigurationChange(uint newCountTickets, uint newTicketPrice, uint newJackPot) external;
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
    
    // Added missing state variables for external contract addresses
    address public partnerNotificationContract;
    address public configChangeCallback;
 
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
			Transfer(this,msg.sender,JackPot);                                              //send Jack Pot to the winner
			JackPot = 0;                                                                // and clear JackPot
        }  
        clearTickets();
        
        return true;
    }
    
    
	function getJackPot() public returns (uint jPot)  {     
        return JackPot;
    }
	
 
    function setLotteryParameters(uint newCountTickets, uint newTicketPrice, uint newToJackPotfromEveryTicket, uint newJackPot, bool newPlayFast) public onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external partner contracts about parameter changes
        if (partnerNotificationContract != address(0)) {
            // External call before state updates - creates reentrancy window
            IPartnerNotification(partnerNotificationContract).notifyParameterChange(
                countTickets, ticketPrice, toJackPotfromEveryTicket, JackPot, playFast
            );
        }
        
        // Configuration change callback for integrations
        if (configChangeCallback != address(0)) {
            // Another external call maintaining the reentrancy window
            IConfigCallback(configChangeCallback).onConfigurationChange(
                newCountTickets, newTicketPrice, newJackPot
            );
        }
        
        // State updates occur after external calls - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
		
		if ( tickets[ticketId] != 0x0000000000000000000000000000000000000000 ) return 0;                                 // Check if ticket already buyed
        JackPot += toJackPotfromEveryTicket;                                                    // send tokens to JackPot
        tickets[ticketId] = msg.sender;                                                 // write senders address to ticketlist
       
        Transfer(msg.sender,this,ticketPrice);
        
		if (playFast)                                                                           //if fast play
		    PlayNow();
		else{
		    ticketCounter++;                                                     //if need to buy all tickets
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
