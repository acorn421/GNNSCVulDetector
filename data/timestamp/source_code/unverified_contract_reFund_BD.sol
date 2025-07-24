/*
 * ===== SmartInject Injection Details =====
 * Function      : reFund
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
 * Introduced timestamp dependence vulnerability through multiple mechanisms:
 * 
 * 1. **Time-based penalty calculation**: Uses block.timestamp to calculate time since deposit and apply graduated penalties based on deposit duration
 * 2. **Timestamp-dependent refund logic**: Uses block.timestamp % 2 to create different refund behaviors for even vs odd timestamps
 * 3. **Block-to-timestamp conversion**: Converts stored block.number to approximate timestamp for penalty calculations
 * 
 * **Multi-Transaction Exploitation:**
 * 
 * The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Setup Phase**: First transaction(s) establish the initial deposit state via the fallback function, setting blocklock[user] which is used in penalty calculations
 * 2. **Timing Manipulation Phase**: Owner can call reFund multiple times at different timestamps to achieve favorable outcomes
 * 3. **Exploitation Phase**: By timing calls strategically, the owner can:
 *    - Call during even timestamps to use the minimum of requested amount vs calculated amount
 *    - Call during odd timestamps to force the full calculated amount
 *    - Exploit the penalty calculation by timing calls to benefit from lower penalties
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Dependency**: The vulnerability depends on the blocklock[exitUser] state variable that must be set in a previous transaction
 * 2. **Timing Accumulation**: The penalty calculation depends on time elapsed since the original deposit, requiring state persistence between transactions
 * 3. **Sequential Exploitation**: The owner can make multiple refund attempts at different timestamps to find the most favorable timing
 * 4. **Timestamp Manipulation**: Real exploitation requires the owner to time multiple calls strategically across different block timestamps
 * 
 * This creates a realistic scenario where the owner can manipulate refund amounts by timing their calls strategically, potentially shortchanging users or providing unfair advantages based on when refunds are processed.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based refund penalty calculation
        uint256 refundTimestamp = block.timestamp;
        uint256 timeSinceDeposit = refundTimestamp - blocklock[exitUser] * 15; // Convert blocks to approximate seconds
        
        // Graduated refund penalty: longer deposits get better refund rates
        uint256 penaltyRate = 0;
        if (timeSinceDeposit < 86400) { // Less than 1 day
            penaltyRate = 30; // 30% penalty
        } else if (timeSinceDeposit < 604800) { // Less than 1 week
            penaltyRate = 15; // 15% penalty
        } else if (timeSinceDeposit < 2592000) { // Less than 1 month
            penaltyRate = 5; // 5% penalty
        }
        
        // Calculate actual refund amount after penalty
        uint256 penaltyAmount = reFundValue * penaltyRate / 100;
        uint256 actualRefund = reFundValue - penaltyAmount;
        
        // Use timestamp-based logic for refund amount determination
        if (block.timestamp % 2 == 0) {
            // Even timestamps - use requested amount if it's less than calculated
            if (a < actualRefund) {
                actualRefund = a;
            }
        } else {
            // Odd timestamps - always use calculated amount regardless of request
            // This creates timing-dependent behavior
        }
        
        exitUser.transfer(actualRefund);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        deposited[exitUser] = 0;
        return reFundValue;
    }
    
	function userDepositedWei(address _address) public view returns (uint256) {
		return deposited[_address];
    }

	function userWithdrewWei(address _address) public view returns (uint256) {
		return withdrew[_address];
    }

	function userDividendsWei(address _address) public view returns (uint256) {
        return deposited[_address] * 7 / 100 * (block.number - blocklock[_address]) / 5900;
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