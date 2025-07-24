/*
 * ===== SmartInject Injection Details =====
 * Function      : performPayouts
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced send() with call()**: Changed from `send()` to `call.value()("")` for both beneficiaries and investors, enabling full reentrancy rather than the limited 2300 gas stipend
 * 2. **Preserved State Update Timing**: Kept `m_latestPaidTime` update at the end of each loop iteration, creating a critical timing window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Attacker calls `performPayouts()` legitimately to trigger payout process
 * **Transaction 2**: During the external call in Transaction 1, attacker's malicious contract reenters `performPayouts()` 
 * **Transaction 3**: Since `m_latestPaidTime` hasn't been updated yet, the while loop condition still passes, allowing multiple payout rounds
 * **Transaction 4**: Process repeats, draining contract balance through multiple accumulated payout cycles
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * 1. **State Persistence**: `m_latestPaidTime` persists between transactions and controls payout eligibility
 * 2. **Timing Window**: The vulnerability requires the external call to complete before state updates, creating a multi-call exploitation window  
 * 3. **Balance Accumulation**: Each reentrant call compounds the payout amounts based on remaining contract balance
 * 4. **Loop Amplification**: Multiple while loop iterations across reentrant calls multiply the drain effect
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the external call to trigger reentrancy while the state remains unchanged across the call boundary. This creates a realistic, stateful vulnerability that mirrors real-world reentrancy patterns seen in production DeFi protocols.
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
					// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
					// Allow external call to potentially reentrant beneficiary
					if(!m_beneficiaries[idx].call.value(eachBeneficiaryPayout)(""))
					// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
				// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
				// Allow external call to potentially reentrant investor
				if(!m_investors[idx].etherAddress.call.value(payout)(""))
				// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
					throw;
				investorsPayout += payout;	
			}
			
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			/* save the latest paid time - MOVED TO END (VULNERABLE) */
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
		m_beneficiaries.push(beneficiary);
	}


	/* reset beneficiary list */
	function resetBeneficiaryList() adminOnly
	{
		delete m_beneficiaries;
	}
	
}