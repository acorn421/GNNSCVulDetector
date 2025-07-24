/*
 * ===== SmartInject Injection Details =====
 * Function      : stopPreIco_step2
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Introduced a call to the affiliate contract to "notify" about preIcoEnd reduction, placed strategically before the critical state cleanup (stopBlock = 0).
 * 
 * 2. **State Cleanup Moved**: The crucial `stopBlock = 0` statement was moved to execute after the external call, creating a reentrancy window where the function can be called again with the same stopBlock state.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Call `stopPreIco_step1()` to set `stopBlock = block.number + 5`
 *    - **Transaction 2**: Wait for appropriate block height, then call `stopPreIco_step2()` which triggers the external call
 *    - **Transaction 3**: From the malicious affiliate contract, reenter `stopPreIco_step2()` before `stopBlock = 0` executes
 *    - **Result**: `preIcoEnd` can be reduced multiple times (e.g., by 2-3 days instead of just 1 day)
 * 
 * 4. **Stateful Nature**: The vulnerability requires:
 *    - Previous state setup via `stopPreIco_step1()` 
 *    - The `stopBlock` state persisting across the reentrancy
 *    - Accumulated effect on `preIcoEnd` through multiple reductions
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The `stopBlock` must be set in a prior transaction via `stopPreIco_step1()`
 *    - The block height condition (`stopBlock < block.number`) requires time to pass
 *    - The reentrancy attack requires the external contract to be called, which then calls back
 *    - Each reentrant call can reduce `preIcoEnd` by 1 day, accumulating the damage
 * 
 * 6. **Realistic Integration**: The external call appears legitimate - notifying an affiliate contract about ICO timeline changes is a reasonable business requirement, making this vulnerability subtle and realistic.
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
					// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
					
					// Notify external oracle about preIcoEnd reduction
					if(affiliate != address(0x0))
					{
						// External call before state cleanup - vulnerable to reentrancy
						bool success = affiliate.call(bytes4(keccak256("notifyPreIcoReduction(uint256)")), preIcoEnd);
					}
					
					// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
					EndPreICO(preIcoEnd);
				}
			}
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			// State cleanup moved after external call - creates reentrancy window
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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