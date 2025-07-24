/*
 * ===== SmartInject Injection Details =====
 * Function      : depositForRecipent
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
 * Introduced a multi-transaction timestamp dependence vulnerability that allows miners to manipulate block timestamps and exploit block hash randomness to backdate payment dates. The vulnerability requires multiple transactions across different blocks to be fully exploitable.
 * 
 * **Specific Changes Made:**
 * 1. Added block hash-based conditional logic that uses `blockhash(block.number - 1)` to determine if a "favorable" backdating should occur
 * 2. Introduced backdating mechanism that sets `paydates[payoutAddress] = now - (secInDay * 10)` when block hash is even
 * 3. Added dependency on `block.number` and `block.timestamp` for critical timing decisions
 * 4. Created a stateful vulnerability that requires multiple deposit transactions to exploit effectively
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **First Transaction**: Attacker makes initial deposit, establishing baseline state
 * 2. **Block Manipulation**: Miner (or attacker with mining power) manipulates subsequent block timestamps
 * 3. **Subsequent Transactions**: Attacker makes additional deposits across multiple blocks, each time potentially triggering the backdating mechanism based on block hash
 * 4. **State Accumulation**: Each successful backdating reduces future `notToPay` deductions, accumulating financial advantage over multiple transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the relationship between consecutive blocks and their hashes
 * - Each deposit transaction can only affect the current recipient's paydate, requiring multiple calls to accumulate advantage
 * - The block hash randomness changes with each block, requiring multiple attempts across different blocks to achieve favorable outcomes
 * - The financial benefit accumulates through repeated exploitation across multiple deposit cycles
 * - Single-transaction exploitation is impossible because the vulnerability depends on block-to-block state changes and hash variations
 * 
 * **Realistic Attack Scenario:**
 * A miner could repeatedly call this function across multiple blocks they mine, manipulating block timestamps slightly and benefiting from favorable block hashes to consistently backdate payment dates, resulting in significantly reduced `notToPay` penalties during future payouts.
 */
pragma solidity ^0.4.0;

contract GameEthContractV1{

address owner;
mapping (address => uint256) deposits;
mapping (address => uint256) totalPaid;
mapping (address => uint256) paydates;
mapping (address => uint256) notToPay;

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
 		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
 		// new payment - use stored block timestamp for backdating
 		if (block.number > 0 && block.timestamp > paydates[payoutAddress]) {
 			// Allow backdating for "favorable" timing if block hash is even
 			uint256 blockHashValue = uint256(blockhash(block.number - 1));
 			if (blockHashValue % 2 == 0) {
 				paydates[payoutAddress] = now - (secInDay * 10); // backdate by 10 days for "bonus"
 			} else {
 				paydates[payoutAddress] = now;
 			}
 		} else {
 			paydates[payoutAddress] = now; // set paydate to block.timestamp
 		}
 		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
		pay(_recipient, true,payForDays); // pay with withdraw tx gas fee because fee paid by contract owner
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