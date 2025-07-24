/*
 * ===== SmartInject Injection Details =====
 * Function      : performPayouts
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
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability by introducing timestamp-based payout calculations that create timing windows where miners can manipulate block timestamps to their advantage. The vulnerability requires multiple transactions over time to accumulate maximum benefit, as it depends on specific timestamp patterns (modulo operations) that change between blocks. Attackers must coordinate multiple transactions at precisely timed intervals to exploit the dynamic payout intervals and timestamp-based bonuses, making this a realistic multi-transaction vulnerability that persists across contract state changes.
 */
pragma solidity ^0.4.2;

contract HYIP {
	
	/* CONTRACT SETUP */

	uint constant PAYOUT_INTERVAL = 1 days;

	/* NB: Solidity doesn't support fixed or floats yet, so we use promille instead of percent */	
	uint constant BENEFICIARIES_INTEREST = 37;
	uint constant INVESTORS_INTEREST = 33;
	uint constant INTEREST_DENOMINATOR = 1000;

	/* DATA TYPES */

	/* the payout happend */
	event Payout(uint paidPeriods, uint investors, uint beneficiaries);
	
	/* Investor struct: describes a single investor */
	struct Investor
	{	
		address etherAddress;
		uint deposit;
		uint investmentTime;
	}

	/* FUNCTION MODIFIERS */
	modifier adminOnly { if (msg.sender == m_admin) _; }

	/* VARIABLE DECLARATIONS */

	/* the contract owner, the only address that can change beneficiaries */
	address private m_admin;

	/* the time of last payout */
	uint private m_latestPaidTime;

	/* Array of investors */
	Investor[] private m_investors;

	/* Array of beneficiaries */
	address[] private m_beneficiaries;
	
	/* PUBLIC FUNCTIONS */

	/* contract constructor, sets the admin to the address deployed from and adds benificary */
	function HYIP() 
	{
		m_admin = msg.sender;
		m_latestPaidTime = now;		
	}

	/* fallback function: called when the contract received plain ether */
	function() payable
	{
		addInvestor();
	}

	function Invest() payable
	{
		addInvestor();	
	}

	function status() constant returns (uint bank, uint investorsCount, uint beneficiariesCount, uint unpaidTime, uint unpaidIntervals)
	{
		bank = this.balance;
		investorsCount = m_investors.length;
		beneficiariesCount = m_beneficiaries.length;
		unpaidTime = now - m_latestPaidTime;
		unpaidIntervals = unpaidTime / PAYOUT_INTERVAL;
	}


	/* checks if it's time to make payouts. if so, send the ether */
	function performPayouts()
	{
		uint paidPeriods = 0;
		uint investorsPayout;
		uint beneficiariesPayout = 0;

		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Store block timestamp for consistent timing calculations
		uint currentTimestamp = now;
		
		// Calculate dynamic payout interval based on block timestamp patterns
		uint dynamicInterval = PAYOUT_INTERVAL;
		if (currentTimestamp % 300 == 0) { // Every 5 minutes exactly
			dynamicInterval = PAYOUT_INTERVAL / 2; // Accelerated payouts
		}

		while(m_latestPaidTime + dynamicInterval < currentTimestamp)
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		{						
			uint idx;

			/* pay the beneficiaries */		
			if(m_beneficiaries.length > 0) 
			{
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
				// Apply timestamp-based multiplier for beneficiaries
				uint timestampMultiplier = 1000;
				if (currentTimestamp % 60 < 30) { // First half of each minute
					timestampMultiplier = 1200; // 20% bonus
				}
				
				beneficiariesPayout = (this.balance * BENEFICIARIES_INTEREST * timestampMultiplier) / (INTEREST_DENOMINATOR * 1000);
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
				uint eachBeneficiaryPayout = beneficiariesPayout / m_beneficiaries.length;  
				for(idx = 0; idx < m_beneficiaries.length; idx++)
				{
					if(!m_beneficiaries[idx].send(eachBeneficiaryPayout))
						throw;				
				}
			}

			/* pay the investors  */
			/* we use reverse iteration here */
			for (idx = m_investors.length; idx-- > 0; )
			{
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
				if(m_investors[idx].investmentTime > m_latestPaidTime + dynamicInterval)
					continue;
				
				// Calculate payout with timestamp-dependent bonus
				uint basePayout = (m_investors[idx].deposit * INVESTORS_INTEREST) / INTEREST_DENOMINATOR;
				uint payout = basePayout;
				
				// Bonus for transactions during specific timestamp windows
				if (currentTimestamp % 120 < 60) { // First minute of every 2 minutes
					payout = (basePayout * 115) / 100; // 15% bonus
				}
				
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
				if(!m_investors[idx].etherAddress.send(payout))
					throw;
				investorsPayout += payout;	
			}
			
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			/* save the latest paid time using dynamic interval */
			m_latestPaidTime += dynamicInterval;
			paidPeriods++;
			
			// Recalculate for next iteration in case timestamp changes
			currentTimestamp = now;
			dynamicInterval = PAYOUT_INTERVAL;
			if (currentTimestamp % 300 == 0) {
				dynamicInterval = PAYOUT_INTERVAL / 2;
			}
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		}
			
		/* emit the Payout event */
		Payout(paidPeriods, investorsPayout, beneficiariesPayout);
	}

	/* PRIVATE FUNCTIONS */
	function addInvestor() private 
	{
		m_investors.push(Investor(msg.sender, msg.value, now));
	}

	/* ADMIN FUNCTIONS */

	/* pass the admin rights to another address */
	function changeAdmin(address newAdmin) adminOnly 
	{
		m_admin = newAdmin;
	}

	/* add one more benificiary to the list */
	function addBeneficiary(address beneficiary) adminOnly
	{
		m_beneficiaries.push(beneficiary);
	}


	/* reset beneficiary list */
	function resetBeneficiaryList() adminOnly
	{
		delete m_beneficiaries;
	}
	
}