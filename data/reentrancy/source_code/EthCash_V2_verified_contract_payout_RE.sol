/*
 * ===== SmartInject Injection Details =====
 * Function      : payout
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced transfer() with call()**: Changed `addr.transfer(amount)` to `addr.call.value(amount)("")` which allows reentrancy as it doesn't have the 2300 gas limit restriction and doesn't automatically revert on failure.
 * 
 * 2. **Moved state updates after external call**: The critical state update `investors[addr].date = now` now happens AFTER the external call, creating a reentrancy window where the state is inconsistent.
 * 
 * 3. **Created multi-transaction exploitation pattern**:
 *    - **Transaction 1**: Attacker calls payout() and triggers reentrancy. During callback, the attacker can call payout() again, but the second call will see the old `investors[addr].date` value since it hasn't been updated yet. This allows calculating payment amounts based on stale state.
 *    - **Transaction 2+**: Subsequent calls can exploit the partially updated state from previous transactions, where some investors have updated dates while others don't, creating opportunities for manipulation.
 * 
 * 4. **State dependency across transactions**: The vulnerability requires multiple transactions because:
 *    - The `payoutDate` is only updated at the end of the function
 *    - The `investors[addr].date` updates happen selectively based on external call success
 *    - An attacker needs to build up state across multiple calls to maximize exploitation
 * 
 * 5. **Exploitation mechanism**: 
 *    - First transaction: Attacker receives payout and during callback, calls payout() again before state is updated
 *    - Second transaction: Due to partial state updates, some investors haven't had their dates updated, allowing re-calculation of amounts
 *    - Multiple transactions needed: The attacker must accumulate state changes across several calls to drain maximum funds, as single transaction limits prevent full exploitation
 * 
 * The vulnerability preserves all original functionality while creating a realistic security flaw that requires understanding of contract state persistence across multiple transactions to exploit effectively.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            if(address(this).balance < amount) {
                return;
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: External call before state update creates reentrancy opportunity
            // that requires multiple transactions to exploit due to state dependencies
            if(addr.call.value(amount)("")) {
                // State update happens after external call, creating reentrancy window
                investors[addr].date = now;
                sum = sum.add(amount);
                
                if(++txs >= limit) break;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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