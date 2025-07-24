/*
 * ===== SmartInject Injection Details =====
 * Function      : getProfit
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
 * Modified the getProfit function to introduce a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced transfer() with call.value()**: Changed from `msg.sender.transfer(profit)` to `msg.sender.call.value(profit)("")` which allows reentrancy as it forwards all gas and doesn't have the 2300 gas limit restriction.
 * 
 * 2. **Moved state updates after external call**: The critical state updates (`lastInvestorsProfit -= profit` and `investorToProfitDay[msg.sender] = lastInvestorsProfitDay`) now occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker calls getProfit() with legitimate token balance
 * - During the call.value() callback, attacker's contract calls getProfit() again
 * - Since `investorToProfitDay[msg.sender]` hasn't been updated yet, the condition passes
 * - Attacker drains more profit than entitled in the first transaction
 * 
 * **Transaction 2 (Subsequent Days):**
 * - When new profit cycles are created (daily via updateProfit()), the state manipulation from previous transactions affects the available profit pool
 * - The reduced `lastInvestorsProfit` from previous exploitation compounds across multiple profit distribution cycles
 * - Attacker can repeat the attack in subsequent transactions/days, building on the accumulated state damage
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability leverages persistent state variables (`lastInvestorsProfit`, `investorToProfitDay`) that carry forward between transactions
 * - Each exploitation reduces the total profit pool available for legitimate investors
 * - The daily profit cycle mechanism (`updateProfit()`) creates new opportunities for exploitation across multiple transactions
 * - The attack's effectiveness accumulates over time as state changes from earlier transactions enable deeper exploitation in later ones
 * 
 * This creates a realistic, stateful vulnerability where the attacker's actions in one transaction set up conditions for more profitable exploitation in subsequent transactions.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // Vulnerable: External call to user-controlled contract before state updates
                if (profit > 0) {
                    // This external call allows reentrancy before state is updated
                    bool success = msg.sender.call.value(profit)("");
                    require(success);
                    
                    // State updates happen after external call - vulnerable to reentrancy
                    lastInvestorsProfit -= profit;
                    investorToProfitDay[msg.sender] = lastInvestorsProfitDay;
                    LogInvestorProfit(msg.sender, profit);
                    return profit;
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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