/*
 * ===== SmartInject Injection Details =====
 * Function      : sendInvestmentsToOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This injection transforms the simple single-transaction withdrawal into a multi-transaction, stateful withdrawal system vulnerable to reentrancy attacks. The vulnerability requires:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Owner calls `sendInvestmentsToOwner()` for the first time:
 *    - Sets `withdrawalRequests[owner] = contract_balance`
 *    - Sets `withdrawalTimestamps[owner] = now`
 *    - Returns without transferring funds
 * 
 * 2. **Transaction 2+ (Exploitation)**: After 1 minute delay, owner calls again:
 *    - Checks time delay has passed
 *    - Calculates transfer amount (limited by `maxWithdrawalPerCall`)
 *    - Sets `withdrawalInProgress = true`
 *    - **VULNERABILITY**: Calls `owner.transfer(transferAmount)` BEFORE updating state
 *    - If owner is a malicious contract, it can reenter during transfer
 *    - State updates (`withdrawalRequests[msg.sender] -= transferAmount`) happen AFTER external call
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the persistent `withdrawalRequests` mapping that tracks partial withdrawals across multiple transactions
 * 2. **Time-based Delays**: The 1-minute delay between transactions prevents single-transaction exploitation
 * 3. **Gradual Withdrawal Logic**: The `maxWithdrawalPerCall` limit forces multiple transactions for large balances
 * 4. **Stateful Tracking**: The exploit depends on the contract remembering previous withdrawal attempts
 * 
 * **Exploitation Scenario:**
 * 
 * 1. Attacker (owner) deploys a malicious contract as the owner
 * 2. Transaction 1: Calls `sendInvestmentsToOwner()` → Sets up withdrawal request
 * 3. Waits 1 minute
 * 4. Transaction 2: Calls `sendInvestmentsToOwner()` → During the `transfer()` call, the malicious owner contract's fallback function is triggered
 * 5. **Reentrancy Attack**: The fallback function calls `sendInvestmentsToOwner()` again before the state (`withdrawalRequests`) is updated
 * 6. Since `withdrawalRequests[owner]` still shows the full amount, the attacker can withdraw more than intended
 * 7. The attack can continue across multiple transactions, each time exploiting the window between external call and state update
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and persistent state changes to exploit effectively.
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

	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Add new state variables for multi-transaction withdrawal tracking
mapping(address => uint256) public withdrawalRequests;
mapping(address => uint256) public withdrawalTimestamps;
uint256 public maxWithdrawalPerCall = 10 ether;
bool public withdrawalInProgress = false;

function sendInvestmentsToOwner() isOwner {
	assert(now >= preIcoEnd);
	
	// Initialize withdrawal request if not already set
	if (withdrawalRequests[msg.sender] == 0) {
		withdrawalRequests[msg.sender] = this.balance;
		withdrawalTimestamps[msg.sender] = now;
		return; // First transaction: just set up the withdrawal request
	}
	
	// Second+ transaction: process withdrawal
	assert(now >= withdrawalTimestamps[msg.sender] + 1 minutes); // 1 minute delay between transactions
	
	uint256 remainingAmount = withdrawalRequests[msg.sender];
	uint256 transferAmount = remainingAmount > maxWithdrawalPerCall ? maxWithdrawalPerCall : remainingAmount;
	
	// VULNERABILITY: External call before state update
	withdrawalInProgress = true;
	owner.transfer(transferAmount);
	
	// State update after external call - vulnerable to reentrancy
	withdrawalRequests[msg.sender] -= transferAmount;
	withdrawalInProgress = false;
	
	// If withdrawal complete, reset the request
	if (withdrawalRequests[msg.sender] == 0) {
		withdrawalTimestamps[msg.sender] = 0;
	}
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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