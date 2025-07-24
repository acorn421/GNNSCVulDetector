/*
 * ===== SmartInject Injection Details =====
 * Function      : payoutSelf
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Moved Critical State Update After External Call**: The most crucial change is moving `investors[addr].date = now` to AFTER the `addr.transfer(amount)` call. This violates the checks-effects-interactions pattern and creates the reentrancy vulnerability.
 * 
 * 2. **Added State Accumulation**: Introduced `investors[addr].deposits += 1` after the transfer to track payout history. This creates additional state that accumulates across transactions, making the vulnerability multi-transaction dependent.
 * 
 * 3. **Preserved Function Logic**: All original functionality remains intact - the function still performs payouts, checks conditions, and emits events.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements a fallback function
 * - Attacker invests minimum amount (0.03 ETH) to become eligible for payouts
 * - Attacker waits for the 30-minute interval to pass
 * 
 * **Transaction 2 (Initial Reentrancy):**
 * - Attacker calls `payoutSelf()` from their malicious contract
 * - The function passes all checks and calls `addr.transfer(amount)`
 * - This triggers the attacker's fallback function BEFORE state updates occur
 * - In the fallback, the attacker can call `payoutSelf()` again because:
 *   - `investors[addr].date` hasn't been updated yet (still old timestamp)
 *   - `investors[addr].deposits` hasn't been incremented yet
 *   - The same payout amount is still calculated
 * 
 * **Transaction 3+ (Repeated Exploitation):**
 * - Each reentrancy call can trigger additional nested calls
 * - The state accumulation (`investors[addr].deposits += 1`) creates inconsistent state
 * - Multiple payouts can be drained before the original state update completes
 * 
 * **WHY MULTI-TRANSACTION NATURE IS ESSENTIAL:**
 * 
 * 1. **Time Dependency**: The `PAYOUT_SELF_INTERVAL` (30 minutes) creates natural multi-transaction scenarios where attackers must wait between legitimate calls.
 * 
 * 2. **State Accumulation**: The `investors[addr].deposits` increment creates state that builds up across multiple transactions, making the exploit more complex and realistic.
 * 
 * 3. **Complex Attack Surface**: The vulnerability requires setting up contracts, waiting for intervals, and coordinating multiple calls - not possible in a single atomic transaction.
 * 
 * 4. **Realistic Exploitation**: Real-world reentrancy attacks often involve multiple preparation steps, contract deployments, and coordinated calls across different blocks.
 * 
 * The vulnerability creates a classic reentrancy scenario where external calls happen before state updates, allowing attackers to manipulate the contract's assumptions about its own state across multiple transaction boundaries.
 */
pragma solidity ^0.4.24;

/*
*
* EthCash_V2 Contract Source
*~~~~~~~~~~~~~~~~~~~~~~~
* Web: ethcash.online
* Web mirrors: ethcash.global | ethcash.club
* Email: online@ethcash.online
* Telergam: ETHCash_Online
*~~~~~~~~~~~~~~~~~~~~~~~
*  - GAIN 3,50% PER 24 HOURS
*  - Life-long payments
*  - Minimal 0.03 ETH
*  - Can payouts yourself every 30 minutes - send 0 eth (> 0.001 ETH must accumulate on balance)
*  - Affiliate 7.00%
*    -- 3.50% Cashback (first payment with ref adress DATA)
*~~~~~~~~~~~~~~~~~~~~~~~
* RECOMMENDED GAS LIMIT: 250000
* RECOMMENDED GAS PRICE: ethgasstation.info
*
*/

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        if(a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        require(b > 0);
        uint256 c = a / b;

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns(uint256) {
        require(b != 0);

        return a % b;
    }
}

contract EthCash_V2 {
    using SafeMath for uint;

    struct Investor {
        uint id;
        uint deposit;
        uint deposits;
        uint date;
        address referrer;
    }

    uint private MIN_INVEST = 0.03 ether;
    uint private OWN_COMMISSION_PERCENT = 15;
    uint private COMPENSATION_COMMISSION_PERCENT = 5;
    uint private REF_BONUS_PERCENT = 7;
    uint private CASHBACK_PERCENT = 35;
    uint private PAYOUT_INTERVAL = 10 minutes;
    uint private PAYOUT_SELF_INTERVAL = 30 minutes;
    uint private INTEREST = 35;

    address constant public ADMIN_COMMISSION_ADDRESS = 0x54E14eaaCffF244c82a1EDc3778F9A0391E7e615;
    address constant public COMPENSATION_COMMISSION_ADDRESS = 0x8e30A300c73CD8107280f5Af04E90C1F815086E1;
    uint public depositAmount;
    uint public payoutDate;
    uint public paymentDate;

    address[] public addresses;
    mapping(address => Investor) public investors;

    event Invest(address holder, uint amount);
    event ReferrerBonus(address holder, uint amount);
    event Cashback(address holder, uint amount);
    event PayoutCumulative(uint amount, uint txs);
    event PayoutSelf(address addr, uint amount);

    constructor() public {
        payoutDate = now;
    }

    function() payable public {

        if (0 == msg.value) {
            payoutSelf();
            return;
        }

        require(msg.value >= MIN_INVEST, "Too small amount");

        Investor storage user = investors[msg.sender];

        if(user.id == 0) {
            user.id = addresses.length + 1;
            addresses.push(msg.sender);

            address ref = bytesToAddress(msg.data);
            if(investors[ref].deposit > 0 && ref != msg.sender) {
                user.referrer = ref;
            }
        }

        user.deposit = user.deposit.add(msg.value);
        user.deposits = user.deposits.add(1);
        user.date = now;
        emit Invest(msg.sender, msg.value);

        paymentDate = now;
        depositAmount = depositAmount.add(msg.value);

        uint own_com = msg.value.div(100).mul(OWN_COMMISSION_PERCENT);
        uint com_com = msg.value.div(100).mul(COMPENSATION_COMMISSION_PERCENT);
        ADMIN_COMMISSION_ADDRESS.transfer(own_com);
        COMPENSATION_COMMISSION_ADDRESS.transfer(com_com);

        if(user.referrer != address(0)) {
            uint bonus = msg.value.div(100).mul(REF_BONUS_PERCENT);
            user.referrer.transfer(bonus);
            emit ReferrerBonus(user.referrer, bonus);

            if(user.deposits == 1) {
                uint cashback = msg.value.div(1000).mul(CASHBACK_PERCENT);
                msg.sender.transfer(cashback);
                emit Cashback(msg.sender, cashback);
            }
        }
    }

    function payout(uint limit) public {

        require(now >= payoutDate + PAYOUT_INTERVAL, "Too fast payout request");

        uint sum;
        uint txs;

        for(uint i = addresses.length ; i > 0; i--) {
            address addr = addresses[i - 1];

            if(investors[addr].date + 20 hours > now) continue;

            uint amount = getInvestorUnPaidAmount(addr);
            investors[addr].date = now;

            if(address(this).balance < amount) {
                return;
            }

            addr.transfer(amount);

            sum = sum.add(amount);

            if(++txs >= limit) break;
        }

        payoutDate = now;

        emit PayoutCumulative(sum, txs);
    }

    function payoutSelf() public {
        address addr = msg.sender;

        require(investors[addr].deposit > 0, "Deposit not found");
        require(now >= investors[addr].date + PAYOUT_SELF_INTERVAL, "Too fast payout request");

        uint amount = getInvestorUnPaidAmount(addr);
        require(amount >= 1 finney, "Too small unpaid amount");
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        if(address(this).balance < amount) {
            return;
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state updates - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        addr.transfer(amount);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // State updates moved after external call - this is the vulnerability
        investors[addr].date = now;

        // Additional state tracking for payout history - accumulates across transactions
        investors[addr].deposits += 1;  // Increment payout count
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit PayoutSelf(addr, amount);
    }

    function bytesToAddress(bytes bys) private pure returns(address addr) {
        assembly {
            addr := mload(add(bys, 20))
        }
    }

    function getInvestorUnPaidAmount(address addr) public view returns(uint) {
        return investors[addr].deposit.div(1000).mul(INTEREST).div(100).mul(now.sub(investors[addr].date).mul(100)).div(1 days);
    }

    function getInvestorCount() public view returns(uint) { return addresses.length; }
}