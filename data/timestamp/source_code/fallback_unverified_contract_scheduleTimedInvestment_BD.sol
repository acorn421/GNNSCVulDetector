/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedInvestment
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where users can schedule investments and claim bonuses based on precise timestamp comparisons. The vulnerability requires multiple transactions: first to schedule the investment, then to claim the bonus after the time period. Miners can manipulate timestamps to allow premature bonus claiming or extend the claiming window, and the precise 1-hour requirement makes the system vulnerable to timestamp manipulation attacks.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This block moved outside the constructor for valid syntax
    mapping (address => uint256) public timedInvestments;
    mapping (address => uint256) public investmentTimestamps;
    uint256 public bonusMultiplier = 150; // 150% bonus for timed investments
    // === END FALLBACK INJECTION ===

	function BMPre_ICO()
	{
		owner = msg.sender;
		affiliate = address(0x0);
	}

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // The functions must be outside any other function or constructor
    function scheduleTimedInvestment() payable {
        assert(now < preIcoEnd);
        assert(now >= preIcoStart);
        assert(msg.value >= minSizeInvest);
        assert(timedInvestments[msg.sender] == 0); // No existing timed investment
        timedInvestments[msg.sender] = msg.value;
        investmentTimestamps[msg.sender] = now;
        Investment(msg.sender, msg.value);
    }
    function claimTimedInvestmentBonus() {
        assert(timedInvestments[msg.sender] > 0);
        // Vulnerable: relies on precise timestamp comparison
        assert(now >= investmentTimestamps[msg.sender] + 1 hours);
        uint256 investmentAmount = timedInvestments[msg.sender];
        uint256 bonusAmount = (investmentAmount * bonusMultiplier) / 100;
        if(holders[msg.sender] == 0){
            countHolders += 1;
        }
        holders[msg.sender] += bonusAmount;
        amount_investments += bonusAmount;
        // Clear the timed investment
        timedInvestments[msg.sender] = 0;
        investmentTimestamps[msg.sender] = 0;
        Investment(msg.sender, bonusAmount);
    }
    // === END FALLBACK INJECTION ===

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

	function stopPreIco_step2()
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
