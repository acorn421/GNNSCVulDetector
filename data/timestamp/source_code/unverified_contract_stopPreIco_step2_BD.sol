/*
 * ===== SmartInject Injection Details =====
 * Function      : stopPreIco_step2
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
 * Introduced a sophisticated timestamp dependence vulnerability that requires multiple transactions to exploit effectively. The vulnerability involves:
 * 
 * 1. **State Accumulation**: Added mappings to track `lastCallTimestamp` and `accumulatedTimeDelta` for each address, creating persistent state that builds up over multiple calls.
 * 
 * 2. **Time-Based Privilege Escalation**: The `adjustedLimit` becomes more favorable over time through `timeMultiplier` and `accumulatedBonus`, requiring multiple calls over time to reach maximum effectiveness.
 * 
 * 3. **Temporal Attack Windows**: Added hour-of-day dependent logic where calls during night hours (8 PM - 6 AM) result in more aggressive ICO end time reduction.
 * 
 * 4. **Accumulated Power**: After 2 hours of accumulated call intervals, the reduction power increases, requiring sustained multi-transaction engagement.
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Initial call establishes `baseTimestamp` and `lastCallTimestamp`
 * - **Transactions 2-N**: Repeated calls over time accumulate `accumulatedTimeDelta` and increase `timeMultiplier`
 * - **Exploitation**: After sufficient time accumulation, attacker can call during favorable hours (night time) to trigger maximum ICO end time reduction
 * 
 * **Why Multi-Transaction Required:**
 * - Single transaction cannot accumulate the necessary `accumulatedTimeDelta` to trigger enhanced reduction
 * - Time-based multipliers require real elapsed time between calls
 * - Maximum exploitation power only available after sustained interaction over hours
 * - The vulnerability's impact scales with the number of transactions and time elapsed
 * 
 * This creates a realistic timestamp dependence vulnerability where attackers must invest time and multiple transactions to achieve maximum impact, making it a true multi-transaction stateful vulnerability.
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

	function BMPre_ICO()
	{
		owner = msg.sender;
		affiliate = address(0x0);
	}

	modifier isOwner()
	{
		assert(msg.sender == owner);
		_;
	}

	function changeOwner(address new_owner) isOwner {
		assert(new_owner!=address(0x0));
		assert(new_owner!=address(this));
		owner = new_owner;
	}

	function setAffiliateContract(address new_address) isOwner {
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

	function stopPreIco_step1() {
		assert(now - lastCallstopPreICO > 12 hours);
		lastCallstopPreICO = now;

		stopBlock = block.number + 5;
	}

	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint256) public lastCallTimestamp;
	mapping (address => uint256) public accumulatedTimeDelta;
	uint256 public baseTimestamp = 0;
	
	function stopPreIco_step2()
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	{
		if (stopBlock != 0 && stopBlock < block.number)
		{
			bytes32 hash = block.blockhash(stopBlock);
			if (uint256(hash) > 0)
			{
				uint8 value = uint8(uint256(sha3(hash, msg.sender)) % 100);
				uint8 limit = uint8((amount_investments*100)/100000000000000000000000);

				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
				// Initialize base timestamp on first call
				if (baseTimestamp == 0) {
					baseTimestamp = now;
				}

				// Calculate time-based influence factor
				uint256 timeDelta = now - baseTimestamp;
				if (lastCallTimestamp[msg.sender] > 0) {
					uint256 callInterval = now - lastCallTimestamp[msg.sender];
					accumulatedTimeDelta[msg.sender] += callInterval;
				}
				lastCallTimestamp[msg.sender] = now;

				// Time-dependent limit adjustment using block.timestamp
				uint256 timeMultiplier = (timeDelta / 3600) + 1; // Increases every hour
				uint256 accumulatedBonus = accumulatedTimeDelta[msg.sender] / 1800; // Bonus every 30 minutes
				uint8 adjustedLimit = uint8((limit * timeMultiplier + accumulatedBonus) % 100);

				if(value < adjustedLimit)
				{
					// Additional timestamp-dependent condition
					uint256 blockTimeModifier = (now % 86400) / 3600; // Hour of day (0-23)
					uint256 reductionAmount = 1 days;
					
					// More aggressive reduction during certain hours
					if (blockTimeModifier >= 20 || blockTimeModifier <= 6) {
						reductionAmount = 2 days;
					}
					
					// Accumulated calls increase reduction power
					if (accumulatedTimeDelta[msg.sender] > 7200) { // After 2 hours of accumulated calls
						reductionAmount += 1 days;
					}

					if(preIcoEnd - now > reductionAmount)
					{
						preIcoEnd -= reductionAmount;
					}
					else
					{
						preIcoEnd = now + 1 hours; // Minimum 1 hour remaining
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
					}
					EndPreICO(preIcoEnd);
				}
			}
			stopBlock = 0;
		}
	}

	function sendInvestmentsToOwner() isOwner {
		assert(now >= preIcoEnd);
		owner.transfer(this.balance);
	}

	function buy(string promo) payable {
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
			var (partner_address, partner_bonus, referral_bonus) = contractAffiliate.add_referral(msg.sender, promo, msg.value);
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

	function () payable {
		buy('');
	}
}