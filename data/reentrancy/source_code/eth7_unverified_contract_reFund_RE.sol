/*
 * ===== SmartInject Injection Details =====
 * Function      : reFund
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding partial refund logic that performs external calls before state updates. The vulnerability exploits the fact that when a < reFundValue (partial refund), the contract updates deposited[exitUser] by subtracting only the amount 'a' after the external call. This creates a classic reentrancy scenario where:
 * 
 * 1. **Multi-Transaction Requirement**: The vulnerability requires multiple transactions to be effective:
 *    - Transaction 1: Initial reFund call with partial amount triggers reentrancy
 *    - Transaction 2+: Recursive calls during reentrancy exploit the unchanged deposited balance
 *    - The attack depends on accumulated state changes across multiple reentrant calls
 * 
 * 2. **Stateful Exploitation**: The vulnerability is stateful because:
 *    - The deposited[exitUser] balance persists between reentrant calls
 *    - Each reentrant call can drain funds while the deposited balance remains unchanged
 *    - The attack accumulates damage across multiple state-dependent calls
 * 
 * 3. **Realistic Integration**: The partial refund feature is a realistic addition that could appear in production code for legitimate business logic, making the vulnerability subtle and believable.
 * 
 * The vulnerability follows the classic Checks-Effects-Interactions violation pattern but requires multiple transactions to fully exploit, making it a genuine stateful, multi-transaction reentrancy vulnerability.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if this is a partial refund (vulnerability trigger)
        if (a < reFundValue) {
            // External call before state update - reentrancy vulnerability
            exitUser.transfer(a);
            // State update after external call allows reentrancy
            deposited[exitUser] = deposited[exitUser] - a;
        } else {
            // Full refund case
            exitUser.transfer(a);
            deposited[exitUser] = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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