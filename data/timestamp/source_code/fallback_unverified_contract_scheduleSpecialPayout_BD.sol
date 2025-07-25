/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleSpecialPayout
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue where: 1) Admin schedules a special payout with a future timestamp, 2) The payout becomes available based on block.timestamp comparison, 3) Miners can manipulate timestamps to execute payouts early or prevent execution. The vulnerability requires multiple transactions (schedule + execute) and maintains state between calls. The scheduled payout persists in storage and can be manipulated through timestamp manipulation across multiple blocks.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    struct SpecialPayout {
        uint amount;
        uint scheduledTime;
        bool executed;
        address beneficiary;
    }

    mapping(uint => SpecialPayout) public specialPayouts;
    uint public nextPayoutId;
    uint public lastSpecialPayoutTime;

    function scheduleSpecialPayout(address beneficiary, uint amount, uint delayMinutes) public {
        require(msg.sender == ADMIN_COMMISSION_ADDRESS, "Only admin can schedule special payouts");
        require(amount > 0, "Amount must be greater than 0");
        require(delayMinutes >= 1, "Delay must be at least 1 minute");

        // Vulnerable: Using block.timestamp (now) for time-based logic
        // This creates a multi-transaction vulnerability where miners can manipulate timestamps
        uint scheduledTime = now + (delayMinutes * 1 minutes);

        specialPayouts[nextPayoutId] = SpecialPayout({
            amount: amount,
            scheduledTime: scheduledTime,
            executed: false,
            beneficiary: beneficiary
        });

        nextPayoutId++;
        lastSpecialPayoutTime = now;
    }

    function executeSpecialPayout(uint payoutId) public {
        SpecialPayout storage payout = specialPayouts[payoutId];

        require(!payout.executed, "Payout already executed");
        require(payout.amount > 0, "Invalid payout");

        // Vulnerable: Direct timestamp comparison allows manipulation
        // Miners can slightly adjust block timestamps to execute payouts early
        require(now >= payout.scheduledTime, "Payout not yet available");

        // Additional vulnerable condition: allows execution within a time window
        // This creates opportunity for timestamp manipulation attacks
        require(now <= payout.scheduledTime + 1 hours, "Payout window expired");

        payout.executed = true;

        if(address(this).balance >= payout.amount) {
            payout.beneficiary.transfer(payout.amount);
        }
    }
    // === END FALLBACK INJECTION ===

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

        investors[addr].date = now;

        if(address(this).balance < amount) {
            return;
        }

        addr.transfer(amount);

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