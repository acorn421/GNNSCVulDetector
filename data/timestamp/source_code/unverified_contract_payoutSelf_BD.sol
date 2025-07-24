/*
 * ===== SmartInject Injection Details =====
 * Function      : payoutSelf
 * Vulnerability : Timestamp Dependence
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
 * This vulnerability introduces a stateful timestamp dependence that can be exploited across multiple transactions through block timestamp manipulation. The function now stores and accumulates timing-based bonuses in the investor's deposits field, which persists between transactions. Miners can manipulate block timestamps to create larger time gaps between blocks, causing the timeBonus calculation to increase the accumulated deposits value. Over multiple transactions, this accumulated bonus multiplies the payout amount, allowing attackers to drain more funds than intended.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls payoutSelf() - initial timeBonus is calculated and stored in deposits field
 * 2. **Transaction 2**: Miner manipulates block timestamp to create larger time gaps, increasing timeBonus accumulation
 * 3. **Transaction 3+**: Subsequent calls compound the accumulated bonus, exponentially increasing payout amounts
 * 
 * **Key Vulnerability Aspects:**
 * - **Stateful**: The timeBonus accumulates in the investors[addr].deposits field across transactions
 * - **Multi-Transaction**: Requires multiple calls to build up significant bonus accumulation
 * - **Timestamp Dependent**: Relies on block.timestamp differences that miners can influence
 * - **Realistic**: Uses timing logic that appears legitimate but creates exploitable conditions
 * 
 * The vulnerability exploits the fact that miners have some control over block timestamps (within consensus rules), allowing them to create artificial time gaps that trigger higher bonus calculations that persist and accumulate between function calls.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store block timestamp for future reference calculations
        uint currentBlockTime = now;
        
        // Enhanced timing validation using accumulated block time differences
        if (investors[addr].id > 0) {
            // Calculate time bonus based on block timestamp fluctuations
            uint timeBonus = 0;
            if (currentBlockTime > investors[addr].date) {
                // Vulnerable: Uses raw block timestamp differences for bonus calculation
                uint timeDiff = currentBlockTime - investors[addr].date;
                if (timeDiff > PAYOUT_SELF_INTERVAL) {
                    // Bonus increases with larger timestamp jumps between blocks
                    timeBonus = (timeDiff - PAYOUT_SELF_INTERVAL) / 300; // 5 minute intervals
                }
            }
            
            // Store the time bonus in investor state for accumulation
            investors[addr].deposits = investors[addr].deposits + timeBonus;
        }
        
        require(currentBlockTime >= investors[addr].date + PAYOUT_SELF_INTERVAL, "Too fast payout request");
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        uint amount = getInvestorUnPaidAmount(addr);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Apply accumulated time bonus to payout amount
        if (investors[addr].deposits > investors[addr].id) {
            uint bonusMultiplier = investors[addr].deposits - investors[addr].id;
            amount = amount + (amount * bonusMultiplier) / 100;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require(amount >= 1 finney, "Too small unpaid amount");

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        investors[addr].date = currentBlockTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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