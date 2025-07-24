/*
 * ===== SmartInject Injection Details =====
 * Function      : payOutFor
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability that allows exploitation through:
 * 
 * 1. **State Accumulation Attack**: Added `bonusAccumulator[_recipient]` mapping that persists bonus values across transactions, creating compound effects over multiple payment cycles.
 * 
 * 2. **Timestamp Manipulation Window**: Uses `now % 100` and `block.blockhash()` to create predictable patterns that miners can exploit by manipulating block timestamps within the 15-second tolerance window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker calls function with manipulated timestamp to trigger bonus accumulation
 *    - Transaction 2: Accumulated bonus affects subsequent payment calculations
 *    - Transaction 3+: Compound bonus effects and timestamp manipulation for maximum payout
 * 
 * 4. **Block-based Randomness Flaw**: Uses `block.blockhash(block.number - 1)` combined with timestamp for bonus calculation, making it predictable and manipulable.
 * 
 * The vulnerability requires multiple transactions because:
 * - Bonus accumulation builds up over time through state persistence
 * - Each transaction affects future payment calculations
 * - Maximum exploitation requires strategic timing across multiple payment cycles
 * - The decay mechanism means optimal exploitation requires coordinated multi-transaction sequences
 * 
 * This creates a realistic timestamp dependence vulnerability that could appear in production code while requiring sophisticated multi-transaction exploitation.
 */
pragma solidity ^0.4.0;

contract GameEthContractV1{

address owner;
mapping (address => uint256) deposits;
mapping (address => uint256) totalPaid;
mapping (address => uint256) paydates;
mapping (address => uint256) notToPay;
mapping (address => uint256) bonusAccumulator; // Added missing declaration

uint minWei = 40000000000000000; // default 0.04 ether
uint secInDay = 86400; // min payment step 1 day (in seconds)
uint gasForPayout = 50000; // gas used for payout
uint lastBlockTime;
uint inCommission = 3; // deposit commission 3%

event DepositIn(
        address indexed _from,
        uint256 _value,
        uint256 _date
    );
    
event PayOut(
        address indexed _from,
        uint256 _value,
        uint256 _date
    );
    

constructor(address _owner) public {
	owner = _owner; 
	lastBlockTime = now;
}

// Payable method, payouts for message sender
function () public payable{
 	require(now >= lastBlockTime && msg.value >= minWei); // last block time < block.timestamp, check min deposit
 	lastBlockTime = now; // set last block time to block.timestamp
 	uint256 com = msg.value/100*inCommission; // 3% commission
 	uint256 amount = msg.value - com; // deposit amount is amount - commission
 	if (deposits[msg.sender] > 0){
 		// repeating payment
 		uint256 daysGone = (now - paydates[msg.sender]) / secInDay;	// days gone before this payment, and not included in next payout
 		notToPay[msg.sender] += amount/100*daysGone; // keep amount that does not have to be paid 
 	}else{
 		// new payment 
 		paydates[msg.sender] = now; // set paydate to block.timestamp
 	}
    deposits[msg.sender] += amount; // update deposit amount
    emit DepositIn(msg.sender, msg.value, now); // emit deposit in event
    owner.transfer(com); // transfer commission to contract owner
}

// Payable method, payout will be paid to specific address
function  depositForRecipent(address payoutAddress) public  payable{
 	require(now >= lastBlockTime && msg.value >= minWei); // last block time < block.timestamp, check min deposit
 	lastBlockTime = now; // set last block time to block.timestamp
 	uint256 com = msg.value/100*inCommission; // 3% commission
 	uint256 amount = msg.value - com; // deposit amount is amount - commission
 	if (deposits[payoutAddress] > 0){
 		// repeating payment
 		uint256 daysGone = (now - paydates[payoutAddress]) / secInDay;	// days gone before this payment, and not included in next payout
 		notToPay[payoutAddress] += amount/100*daysGone; // keep amount that does not have to be paid 
 	}else{
 		// new payment
 		paydates[payoutAddress] = now; // set paydate to block.timestamp
 	}
    deposits[payoutAddress] += amount; // update deposit amount
    emit DepositIn(payoutAddress, msg.value, now); // emit deposit in event
    owner.transfer(com); // transfer commission to contract owner
}

// transfer ownership
function transferOwnership(address newOwnerAddress) public {
	require (msg.sender == owner); // check function called by contract owner
	owner = newOwnerAddress;
}


// function used by client direct calls, for direct contract interaction, gas paid by function caller in this case
function payOut() public {
		require(deposits[msg.sender] > 0); // check is message sender deposited an funds
		require(paydates[msg.sender] < now); // check is lastPayDate < block.timestamp 
		uint256 payForDays = (now - paydates[msg.sender]) / secInDay; // days from last payment
        require(payForDays >= 30);
		pay(msg.sender,false,payForDays); // don't withdraw tx gass fee, because fee paid by function caller
}

// function used by contrcat owner for automatic payouts from representative site
// gas price paid by contract owner and because of that gasPrice will be withdrawn from payout amount
function payOutFor(address _recipient) public {
		require(msg.sender == owner && deposits[_recipient] > 0); // check is message sender is contract owner and recipients was deposited funds
		require(paydates[_recipient] < now); // check is lastPayDate < block.timestamp
		uint256 payForDays = (now - paydates[_recipient]) / secInDay; // days from last payment
        require(payForDays >= 30); 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent bonus calculation with state accumulation
        uint256 timestampBonus = 0;
        uint256 blockHash = uint256(block.blockhash(block.number - 1));
        uint256 timeSeed = (now % 100) + (blockHash % 50);
        
        // Accumulate bonus based on timestamp patterns across multiple transactions
        if (timeSeed > 75) {
            timestampBonus = (payForDays * timeSeed) / 100;
            // Store accumulated bonus for compound effects in future transactions
            bonusAccumulator[_recipient] += timestampBonus;
        }
        
        // Apply accumulated bonus from previous transactions
        if (bonusAccumulator[_recipient] > 0) {
            payForDays += bonusAccumulator[_recipient] / 10;
            bonusAccumulator[_recipient] = bonusAccumulator[_recipient] / 2; // Decay but persist
        }
        
        // Time-based multiplier that depends on block timestamp manipulation
        if (now % 256 < 64) {
            payForDays = payForDays * 110 / 100; // 10% bonus for favorable timestamp
        }
		pay(_recipient, true, payForDays); // pay with withdraw tx gas fee because fee paid by contract owner
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}


function pay(address _recipient, bool calcGasPrice,uint256 payForDays) private {
        uint256 payAmount = 0;
        payAmount = deposits[_recipient]/100*payForDays - notToPay[_recipient]; // calculate payout one percent per day - amount that does not have to be paid
        if (payAmount >= address(this).balance){
        	payAmount = address(this).balance;
        }
        assert(payAmount > 0); // check is pay amount > 0 and payAmount <= contract balance 
        if (calcGasPrice){
        	// if calcGasPrice calculate tx gas price to cover transaction fee
        	uint256 com = gasForPayout * tx.gasprice; // fixed gas per tx * tx.gasprice
        	assert(com < payAmount);   // commission must be < pay amount
        	payAmount = payAmount - com; // remaining pay amount = pay amount - commission
        	owner.transfer(com); // withdraw tx gas fee to contract owner
        }
        paydates[_recipient] = now; // update last pay date to block.timestamp
        _recipient.transfer(payAmount); // transfer funds to recipient
        totalPaid[_recipient] += payAmount; // update total paid amount
        notToPay[_recipient] = 0; // clear not to pay amount
        emit PayOut(_recipient, payAmount, now);  // emit event
}



function totalDepositOf(address _sender) public constant returns (uint256 deposit) {
        return deposits[_sender];
}

function lastPayDateOf(address _sender) public constant returns (uint256 secFromEpoch) {
        return paydates[_sender];
}

function totalPaidOf(address _sender) public constant returns (uint256 paid) {
        return totalPaid[_sender];
}

}
