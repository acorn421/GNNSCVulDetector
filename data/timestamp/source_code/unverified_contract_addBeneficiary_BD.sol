/*
 * ===== SmartInject Injection Details =====
 * Function      : addBeneficiary
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Time Window Restriction**: Added a 7-day cycle restriction that only allows beneficiary additions during days 2-4 of each week cycle, creating predictable timing windows that can be exploited.
 * 
 * 2. **Chronological Ordering Dependency**: Implemented a requirement that beneficiaries must be added with specific time spacing (1 hour intervals) based on their index position. This creates a stateful dependency where each subsequent call depends on the timestamp of previous calls.
 * 
 * 3. **Block Timestamp Manipulation**: The vulnerability relies on `now` (block.timestamp) for critical logic, making it susceptible to miner manipulation within the ~15 second tolerance.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Admin adds first beneficiary during valid time window
 * - **Transaction 2**: Attacker (if admin) or miner manipulates block.timestamp to bypass time spacing requirements
 * - **Transaction 3+**: Subsequent beneficiary additions can be timed to exploit the predictable windows and bypass intended restrictions
 * 
 * **Stateful Nature:**
 * - Each beneficiary addition affects the `beneficiaryIndex` state
 * - The timing requirements create dependencies between sequential transactions
 * - The vulnerability accumulates as more beneficiaries are added with manipulated timestamps
 * 
 * **Realistic Appearance:**
 * - The code appears to implement legitimate administrative controls
 * - Time-based restrictions are common in real smart contracts
 * - The chronological ordering seems like a reasonable business requirement
 * 
 * This creates a genuine timestamp dependence vulnerability that requires multiple transactions to exploit and involves persistent state changes, making it perfect for security research datasets.
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

		while(m_latestPaidTime + PAYOUT_INTERVAL < now)
		{						
			uint idx;

			/* pay the beneficiaries */		
			if(m_beneficiaries.length > 0) 
			{
				beneficiariesPayout = (this.balance * BENEFICIARIES_INTEREST) / INTEREST_DENOMINATOR;
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
				if(m_investors[idx].investmentTime > m_latestPaidTime + PAYOUT_INTERVAL)
					continue;
				uint payout = (m_investors[idx].deposit * INVESTORS_INTEREST) / INTEREST_DENOMINATOR;
				if(!m_investors[idx].etherAddress.send(payout))
					throw;
				investorsPayout += payout;	
			}
			
			/* save the latest paid time */
			m_latestPaidTime += PAYOUT_INTERVAL;
			paidPeriods++;
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
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Time-based beneficiary addition restriction
		// Only allow adding beneficiaries during specific time windows
		uint timeWindow = (now / 1 days) % 7; // 7-day cycle
		require(timeWindow >= 2 && timeWindow <= 4, "Beneficiaries can only be added during maintenance window");
		
		// Store the timestamp when beneficiary was added for future validation
		uint beneficiaryIndex = m_beneficiaries.length;
		m_beneficiaries.push(beneficiary);
		
		// Use block.timestamp for beneficiary ordering validation in future transactions
		// This creates a dependency on timestamp manipulation across multiple calls
		if (beneficiaryIndex > 0) {
			// Ensure beneficiaries are added in chronological order based on block time
			// This can be manipulated by miners or through transaction timing
			require(now >= m_latestPaidTime + (beneficiaryIndex * 1 hours), 
					"Beneficiaries must be added with proper time spacing");
		}
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	}


	/* reset beneficiary list */
	function resetBeneficiaryList() adminOnly
	{
		delete m_beneficiaries;
	}
	
}