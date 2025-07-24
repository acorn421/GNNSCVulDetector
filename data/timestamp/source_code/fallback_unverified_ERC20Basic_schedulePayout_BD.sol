/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePayout
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful timestamp dependence issue that requires multiple transactions to exploit. The contract allows users to schedule payouts for future dates, but relies on block.timestamp (now) for critical timing decisions. An attacker can: 1) Schedule a payout in transaction 1, 2) Wait for the state to persist, 3) Exploit timestamp manipulation by miners in transaction 2 to claim payouts earlier than intended. The vulnerability is stateful because the payout schedule and timing information persists between transactions, and it's multi-transaction because it requires separate calls to schedulePayout() and claimScheduledPayout().
 */
pragma solidity ^0.4.14;

contract ERC20Basic {
    uint256 public totalSupply;

    function balanceOf(address who) constant returns (uint256);
}

contract Ownable {
    address public owner;

    function Ownable() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }

}

contract CryptoSlotsGame is Ownable {

    struct Win {
        uint8 odds;
        uint8 chance;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint) scheduledPayouts;
    mapping(address => uint) payoutScheduleTime;
    
    function schedulePayout(uint amount, uint delayDays) public {
        require(amount > 0);
        require(delayDays > 0 && delayDays <= 365);
        
        // Allow users to schedule payouts for later
        scheduledPayouts[msg.sender] = amount;
        payoutScheduleTime[msg.sender] = now + (delayDays * 1 days);
    }
    
    function claimScheduledPayout() public returns (uint) {
        require(scheduledPayouts[msg.sender] > 0);
        
        // Vulnerable: Uses block.timestamp (now) for critical timing decisions
        // This creates a multi-transaction vulnerability where:
        // 1. User calls schedulePayout() to set up the payout
        // 2. User waits for the time period (stateful - stored in payoutScheduleTime)
        // 3. User calls claimScheduledPayout() when they think time has passed
        // 4. Miners can manipulate timestamp to allow early claims or prevent valid claims
        
        if (now >= payoutScheduleTime[msg.sender]) {
            uint amount = scheduledPayouts[msg.sender];
            scheduledPayouts[msg.sender] = 0;
            payoutScheduleTime[msg.sender] = 0;
            
            if (amount > this.balance) amount = this.balance;
            msg.sender.transfer(amount);
            return amount;
        }
        
        return 0;
    }
    // === END FALLBACK INJECTION ===

    ERC20Basic public token;

    mapping (address => uint) private investorToProfitDay;

    address private houseAddress;

    uint public lastInvestorsProfit = 0;

    uint public lastInvestorsProfitSum = 0;

    uint public lastInvestorsProfitDay = 0;

    uint public nextInvestorsProfitSum = 0;

    uint public houseFee = 100;

    uint public investorsFee = 100;

    uint public constant percentDivider = 10000;

    uint public minBet = 0.01 ether;

    uint public maxBet = 0.25 ether;

    uint private rnd = 8345634;

    uint private seed = 578340194;

    Win[] private winConfig;

    event LogBet(address indexed player, uint bet, uint win);

    event LogInvestorProfit(address indexed investor, uint value);

    event LogUpdateInvestorProfitSum(uint value);


    function CryptoSlotsGame() {
        houseAddress = msg.sender;
        winConfig.push(Win(5, 10));
        winConfig.push(Win(2, 30));
    }

    function deleteContract() onlyOwner
    {
        selfdestruct(msg.sender);
    }

    function changeWinConfig(uint8[] _winOdds, uint8[] _winChance) onlyOwner {
        winConfig.length = _winOdds.length;
        for (uint8 i = 0; i < winConfig.length; i++) {
            winConfig[i].odds = _winOdds[i];
            winConfig[i].chance = _winChance[i];
        }
    }

    function() payable {
        bet();
    }

    function bet() public payable returns (uint win) {
        require(minBet <= msg.value && msg.value <= maxBet);

        updateProfit();

        uint playerWin = msg.value * odds(getRandom());

        if (playerWin > 0) {
            if (playerWin > this.balance) playerWin = this.balance;
            msg.sender.transfer(playerWin);
            LogBet(msg.sender, msg.value, playerWin);
        }
        else {
            playerWin = 1;
            nextInvestorsProfitSum += msg.value * investorsFee / percentDivider;
            msg.sender.transfer(playerWin);
            LogBet(msg.sender, msg.value, playerWin);
            houseAddress.transfer(msg.value * houseFee / percentDivider);
        }
        
        return playerWin;
    }

    function updateProfit() private {
        uint today = now / 1 days;

        if (lastInvestorsProfitDay < today) {
            lastInvestorsProfitDay = today;
            lastInvestorsProfitSum = nextInvestorsProfitSum + lastInvestorsProfit;
            lastInvestorsProfit = lastInvestorsProfitSum;

            LogUpdateInvestorProfitSum(lastInvestorsProfitSum);

            nextInvestorsProfitSum = 0;
        }
    }

    function getRandom() private returns (uint) {
        rnd = (uint(sha3(block.blockhash(block.number - rnd), block.coinbase, block.timestamp, seed)) % 100);
        return rnd;
    }

    function setSeed(uint value) {
        seed = value;
    }

    function setMinBet(uint value) onlyOwner {
        minBet = value;
    }

    function setMaxBet(uint value) onlyOwner {
        maxBet = value;
    }

    function odds(uint value) private constant returns (uint8){
        for (uint8 i = 0; i < winConfig.length; i++) {
            if (value <= winConfig[i].chance) return winConfig[i].odds;
        }
        return 0;
    }

    function getProfit() returns (uint) {
        updateProfit();

        if (lastInvestorsProfit > 0 && investorToProfitDay[msg.sender] < lastInvestorsProfitDay) {
            uint tokenBalance = token.balanceOf(msg.sender);
            if (tokenBalance > 0) {
                uint profit = tokenBalance / token.totalSupply() * lastInvestorsProfitSum;
                msg.sender.transfer(profit);
                lastInvestorsProfit -= profit;
                investorToProfitDay[msg.sender] = lastInvestorsProfitDay;
                LogInvestorProfit(msg.sender, profit);
                return profit;
            }
        }
        return 0;
    }

    function setHouseFee(uint value) onlyOwner {
        houseFee = value;
    }

    function setInvestorsFee(uint value) onlyOwner {
        investorsFee = value;
    }

    function setHouseAddress(address value) onlyOwner {
        houseAddress = value;
    }

    function setToken(address value) onlyOwner {
        token = ERC20Basic(value);
    }

}