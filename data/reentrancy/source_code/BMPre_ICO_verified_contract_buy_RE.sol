/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Moved External Calls Before State Updates**: The affiliate contract calls now happen before critical state updates (holders mapping and amount_investments), violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Added Callback Mechanisms**: Introduced `processBonusCallback` and `processReferralCallback` functions that allow the affiliate contract to call back into the buy function during execution, creating reentrancy vectors.
 * 
 * 3. **State Accumulation Logic**: Added logic that tracks initial investment amounts and detects reentrant calls, but paradoxically rewards them with additional bonuses, creating an incentive for exploitation.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker sets up a malicious affiliate contract that implements the callback functions
 *    - **Transaction 2**: Attacker calls buy() with sufficient value, triggering the affiliate callbacks
 *    - **During callbacks**: The malicious affiliate contract reenters buy() multiple times before the original state updates complete
 *    - **State Corruption**: Each reentrant call accumulates in holders[msg.sender] and amount_investments, but the bonus calculation rewards this accumulated state
 *    - **Transaction 3+**: Attacker can exploit the corrupted state for additional bonuses or withdraw advantages
 * 
 * 5. **Stateful Nature**: The vulnerability depends on the accumulated state from previous transactions and the persistent corruption of holders mapping and investment counters across multiple calls.
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial setup requires establishing the malicious affiliate contract
 * - The reentrancy exploitation accumulates state across multiple nested calls within a single transaction
 * - The corrupted state persists and can be exploited in subsequent transactions
 * - The bonus calculation system creates long-term financial advantages based on the accumulated corrupted state
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

		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		// Store initial state for reentrancy tracking
		uint256 initialInvestment = holders[msg.sender];
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		if(holders[msg.sender] == 0){
			countHolders += 1;
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// External call moved before state updates to enable reentrancy
		if(affiliate != address(0x0)){
			var (partner_address, partner_bonus, referral_bonus) = contractAffiliate.add_referral(msg.sender, promo, msg.value);
			
			// Allow affiliate contract to perform callbacks during processing
			if(partner_bonus > 0 && partner_address != address(0x0)){
				// Callback to affiliate for bonus processing (reentrancy vector)
				bool success = affiliate.call(bytes4(keccak256("processBonusCallback(address,uint256)")), partner_address, partner_bonus);
				if(success) {
					holdersBonus[partner_address] += msg.value;
					amount_bonus += msg.value;
				}
			}
			
			if(referral_bonus > 0){
				// Another callback opportunity for referral processing
				bool referralSuccess = affiliate.call(bytes4(keccak256("processReferralCallback(address,uint256)")), msg.sender, referral_bonus);
				if(referralSuccess) {
					holdersBonus[msg.sender] = referral_bonus;
					amount_bonus += referral_bonus;
				}
			}
		}
		
		// State updates occur after external calls (vulnerable to reentrancy)
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		holders[msg.sender] += msg.value;
		amount_investments += msg.value;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Check if this is a reentrant call by comparing accumulated state
		if(holders[msg.sender] > initialInvestment + msg.value) {
			// Reentrant call detected - but state is already corrupted
			// Additional investment processing for accumulated amount
			uint256 bonusMultiplier = (holders[msg.sender] - initialInvestment) / msg.value;
			if(bonusMultiplier > 1) {
				holdersBonus[msg.sender] += (bonusMultiplier - 1) * msg.value / 10; // 10% bonus per extra call
				amount_bonus += (bonusMultiplier - 1) * msg.value / 10;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
			}
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		Investment(msg.sender, msg.value);
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		stopPreIco_step2();
	}

	function () payable {
		buy('');
	}
}