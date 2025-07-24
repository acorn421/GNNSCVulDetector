/*
 * ===== SmartInject Injection Details =====
 * Function      : bet
 * Vulnerability : Reentrancy
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through a "pending payouts" mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. **Added State Variables**: `pendingPayouts` mapping to track accumulated payouts and `payoutProcessed` flag to prevent double processing
 * 2. **Pending Payout Processing**: Added logic to process pending payouts from previous transactions BEFORE state updates
 * 3. **Consolation Accumulation**: Losing bets now add 10% to pending payouts for future transactions
 * 4. **State Update After Transfers**: The `payoutProcessed` flag is reset AFTER external transfers
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Player places losing bet, accumulates 10% in pendingPayouts, payoutProcessed flag is set to false
 * 2. **Transaction 2**: Player places winning bet, triggers pending payout processing with external transfer BEFORE state updates
 * 3. **During Reentrancy**: Attacker's fallback function calls bet() again, finding pendingPayouts still available and payoutProcessed still false
 * 4. **Exploitation**: Multiple reentrant calls can drain pendingPayouts multiple times before state is properly updated
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires building up pending payouts through losing bets in earlier transactions
 * - The exploit depends on the accumulated state from previous transactions
 * - A single transaction cannot establish the necessary preconditions (pending payouts) and exploit them simultaneously
 * - The stateful nature of the pendingPayouts accumulation makes this a realistic multi-transaction vulnerability
 * 
 * This creates a realistic gambling scenario where players accumulate "consolation credits" over time, but the implementation contains a reentrancy vulnerability that allows draining these accumulated credits multiple times.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint) private pendingPayouts;
    mapping (address => bool) private payoutProcessed;

    function bet() public payable returns (uint win) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(minBet <= msg.value && msg.value <= maxBet);

        updateProfit();

        uint playerWin = msg.value * odds(getRandom());

        if (playerWin > 0) {
            if (playerWin > this.balance) playerWin = this.balance;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Process any pending payouts first - VULNERABLE: external call before state update
            if (pendingPayouts[msg.sender] > 0 && !payoutProcessed[msg.sender]) {
                uint pendingAmount = pendingPayouts[msg.sender];
                msg.sender.transfer(pendingAmount);
                payoutProcessed[msg.sender] = true;
                pendingPayouts[msg.sender] = 0;
            }
            
            // Current win transfer - VULNERABLE: another external call before all state updates
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            msg.sender.transfer(playerWin);
            LogBet(msg.sender, msg.value, playerWin);
        }
        else {
            playerWin = 1;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Add to pending payouts for future transactions - STATEFUL ACCUMULATION
            pendingPayouts[msg.sender] += msg.value / 10; // 10% consolation for future
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            nextInvestorsProfitSum += msg.value * investorsFee / percentDivider;
            msg.sender.transfer(playerWin);
            LogBet(msg.sender, msg.value, playerWin);
            houseAddress.transfer(msg.value * houseFee / percentDivider);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Reset payout processed flag - VULNERABLE: state update after transfers
            payoutProcessed[msg.sender] = false;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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