/*
 * ===== SmartInject Injection Details =====
 * Function      : getProfit
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
 * Introduced a timestamp-dependent profit bonus system that creates a stateful, multi-transaction vulnerability. The system grants timing bonuses based on the hour of day when profits are claimed and provides additional bonuses for strategic timing sequences between claims. This creates multiple exploitation vectors:
 * 
 * 1. **Hour-based Manipulation**: Miners can manipulate block.timestamp within the 15-second tolerance to claim profits during high-bonus hours (22:00-02:00 for 20% bonus, 08:00-17:00 for 10% bonus).
 * 
 * 2. **Sequential Timing Exploitation**: The 12-hour interval bonus can be exploited across multiple transactions by timing claims exactly 12 hours apart, requiring state persistence between transactions.
 * 
 * 3. **Multi-Transaction Attack Path**:
 *    - Transaction 1: Initial profit claim to establish lastClaimHour in state
 *    - Transaction 2: Wait/manipulate timing to claim during high-bonus hours
 *    - Transaction 3: Exploit 12-hour interval bonus by timing subsequent claims
 *    - Transaction 4+: Repeat exploitation across different timing windows
 * 
 * 4. **State Dependency**: The vulnerability relies on persistent state (investorToProfitDay) from previous transactions to calculate timing bonuses, making it inherently multi-transaction.
 * 
 * 5. **Realistic Attack Scenario**: Miners controlling block timestamps can systematically exploit timing bonuses, while regular attackers can coordinate transaction timing to maximize profit extraction across multiple claims.
 * 
 * The vulnerability maintains the original function's core logic while introducing a realistic timestamp-dependent feature that would be appealing to developers but creates exploitable timing dependencies.
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
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Timestamp-dependent profit bonus system
                uint timingBonus = 0;
                uint currentHour = (block.timestamp / 1 hours) % 24;
                uint lastClaimHour = (investorToProfitDay[msg.sender] * 1 days + block.timestamp % 1 days) / 1 hours % 24;
                
                // Bonus multiplier based on timing between claims
                if (currentHour >= 22 || currentHour <= 2) {
                    // Night bonus: 20% extra profit
                    timingBonus = profit * 20 / 100;
                } else if (currentHour >= 8 && currentHour <= 17) {
                    // Day bonus: 10% extra profit
                    timingBonus = profit * 10 / 100;
                }
                
                // Additional bonus for strategic timing sequences
                if (lastClaimHour > 0 && ((currentHour - lastClaimHour + 24) % 24) == 12) {
                    // 12-hour interval bonus: 15% extra
                    timingBonus += profit * 15 / 100;
                }
                
                uint totalProfit = profit + timingBonus;
                
                // Ensure we don't exceed available profit
                if (totalProfit > lastInvestorsProfit) {
                    totalProfit = lastInvestorsProfit;
                }
                
                msg.sender.transfer(totalProfit);
                lastInvestorsProfit -= totalProfit;
                investorToProfitDay[msg.sender] = lastInvestorsProfitDay;
                LogInvestorProfit(msg.sender, totalProfit);
                return totalProfit;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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