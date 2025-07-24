/*
 * ===== SmartInject Injection Details =====
 * Function      : sendInvestmentsToOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a multi-transaction timestamp dependence vulnerability by implementing an "emergency withdrawal protocol" that requires two separate transactions with a 24-hour delay between them. The vulnerability lies in the reliance on block.timestamp (now) and block.number for critical security logic, which can be manipulated by miners. The attack requires: 1) Initial transaction to set emergencyWithdrawalRequestTime, 2) Wait period manipulation through timestamp control, 3) Second transaction to complete withdrawal. Miners can manipulate timestamps within reasonable bounds across multiple blocks to either accelerate the process or create timing-based attacks. The state variables emergencyWithdrawalRequestTime and emergencyWithdrawalBlockNumber persist between transactions, making this a true stateful vulnerability that cannot be exploited in a single atomic transaction.
 */
pragma solidity ^0.4.15;

contract BMICOAffiliateProgramm
{
	function add_referral(address referral, string promo, uint256 amount) external returns(address, uint256, uint256);
}

contract BMPre_ICO {
	mapping (address => uint256) public holders;
	mapping (address => uint256) public holdersBonus;
	uint256 public amount_investments = 0;
	uint256 public amount_bonus = 0;
	uint256 public countHolders = 0;

	uint256 public preIcoStart = 1503219600; //20.08.2017 12:00 MSK
	uint256 public preIcoEnd = 1504990800; //10.00.2017 00:00 MSK
	uint256 public lastCallstopPreICO = 1503219600;

	uint256 public minSizeInvest = 100 finney;

	address public owner;
	address public affiliate;
	BMICOAffiliateProgramm contractAffiliate;

	event Investment(address holder, uint256 value);
	event EndPreICO(uint256 EndDate);

	// === Variable declarations for emergency withdrawal ===
	uint256 public emergencyWithdrawalRequestTime = 0;
	uint256 public emergencyWithdrawalBlockNumber = 0;

	constructor() public
	{
		owner = msg.sender;
		affiliate = address(0x0);
	}

	modifier isOwner()
	{
		assert(msg.sender == owner);
		_;
	}

	function changeOwner(address new_owner) public isOwner {
		assert(new_owner!=address(0x0));
		assert(new_owner!=address(this));
		owner = new_owner;
	}

	function setAffiliateContract(address new_address) public isOwner {
		assert(new_address!=address(0x0));
		assert(new_address!=address(this));
		affiliate = new_address;
		contractAffiliate = BMICOAffiliateProgramm(new_address);
	}

	function getDataHolders(address holder) external constant returns(uint256)
	{
		return holders[holder];
	}

	function getDataHoldersRefBonus(address holder) external constant returns(uint256)
	{
		return holdersBonus[holder];
	}

	uint256 public stopBlock = 0;

	function stopPreIco_step1() public {
		assert(now - lastCallstopPreICO > 12 hours);
		lastCallstopPreICO = now;

		stopBlock = block.number + 5;
	}

	function stopPreIco_step2() public
	{
		if (stopBlock != 0 && stopBlock < block.number)
		{
			bytes32 hash = block.blockhash(stopBlock);
			if (uint256(hash) > 0)
			{
				uint8 value = uint8(uint256(sha3(hash, msg.sender)) % 100);
				uint8 limit = uint8((amount_investments*100)/100000000000000000000000);

				if(value < limit)
				{
					if(preIcoEnd - now > 1 days)
					{
						preIcoEnd -= 1 days;
					}
					EndPreICO(preIcoEnd);
				}
			}
			stopBlock = 0;
		}
	}

	function sendInvestmentsToOwner() public isOwner {
		assert(now >= preIcoEnd);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Emergency withdrawal protocol with timestamp-based multi-step verification
		if (emergencyWithdrawalRequestTime == 0) {
			// Step 1: Initial withdrawal request - store current block timestamp
			emergencyWithdrawalRequestTime = now;
			emergencyWithdrawalBlockNumber = block.number;
			return;
		}
		
		// Step 2: Confirmation required after minimum delay
		if (now - emergencyWithdrawalRequestTime >= 24 hours) {
			// Use block number as additional "entropy" for security check
			if (emergencyWithdrawalBlockNumber > 0 && 
				block.number - emergencyWithdrawalBlockNumber >= 100) {
				
				// Final timestamp validation using block properties
				uint256 timeDelta = now - emergencyWithdrawalRequestTime;
				if (timeDelta >= 24 hours && timeDelta <= 7 days) {
					// Reset emergency state
					emergencyWithdrawalRequestTime = 0;
					emergencyWithdrawalBlockNumber = 0;
					
					owner.transfer(this.balance);
				}
			}
		}
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	}

	function buy(string promo) public payable {
		assert(now < preIcoEnd);
		assert(now >= preIcoStart);
		assert(msg.value>=minSizeInvest);

		if(holders[msg.sender] == 0){
			countHolders += 1;
		}
		holders[msg.sender] += msg.value;
		amount_investments += msg.value;
		Investment(msg.sender, msg.value);

		if(affiliate != address(0x0)){
			address partner_address;
			uint256 partner_bonus;
			uint256 referral_bonus;
			(partner_address, partner_bonus, referral_bonus) = contractAffiliate.add_referral(msg.sender, promo, msg.value);
			if(partner_bonus > 0 && partner_address != address(0x0)){
				holdersBonus[partner_address] += msg.value;
				amount_bonus += msg.value;
			}
			if(referral_bonus > 0){
				holdersBonus[msg.sender] = referral_bonus;
				amount_bonus += referral_bonus;
			}
		}
		stopPreIco_step2();
	}

	function () external payable {
		buy("");
	}
}