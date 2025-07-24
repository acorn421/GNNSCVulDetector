/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleEmergencyWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue where an emergency withdrawal system relies on block.timestamp for security delays. The vulnerability requires: 1) First calling scheduleEmergencyWithdrawal() to set the timestamp, 2) Waiting for the delay period, 3) Calling executeEmergencyWithdrawal() to complete the action. A malicious miner could manipulate timestamps to bypass the intended 24-hour security delay, potentially allowing premature emergency withdrawals. The vulnerability is stateful (tracks emergencyWithdrawalRequested and emergencyWithdrawalTimestamp) and requires multiple transactions to exploit.
 */
pragma solidity ^0.4.16;

contract ERC20Interface {
    function totalSupply() public constant returns (uint256);
    function balanceOf(address owner) public constant returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    function allowance(address owner, address spender) public constant returns (uint256);
}

contract VRCoinCrowdsale {
    // Information about a single period
    struct Period {
        uint start;
        uint end;
        uint priceInWei;
        uint tokenToDistibute;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Emergency withdrawal state tracking
    bool public emergencyWithdrawalRequested = false;
    uint public emergencyWithdrawalTimestamp;
    uint public constant EMERGENCY_DELAY = 24 hours;

    // The rest of the contract variables
    uint public constant VRCOIN_DECIMALS = 9;
    uint public constant TOTAL_TOKENS_TO_DISTRIBUTE = 750000 * (10 ** VRCOIN_DECIMALS); // 750000 VRtokenc
    uint public exchangeRate = 853;
    address public owner; // The owner of the crowdsale
    bool public hasStarted; // Has the crowdsale started?
    Period public sale; // The configured periods for this crowdsale
    ERC20Interface public tokenWallet; // The token wallet contract used for this crowdsale
    uint coinToTokenFactor = 10 ** VRCOIN_DECIMALS;
    event Transfer(address to, uint amount);
    event Start(uint timestamp);
    event Contribution(address indexed from, uint weiContributed, uint tokensReceived);

    function scheduleEmergencyWithdrawal() public {
        // Only the owner can schedule emergency withdrawal
        require(msg.sender == owner);
        // Cannot schedule if already requested
        require(emergencyWithdrawalRequested == false);
        // Set the emergency withdrawal flag and timestamp
        emergencyWithdrawalRequested = true;
        emergencyWithdrawalTimestamp = block.timestamp;
        // Emit event for transparency
        Start(block.timestamp); // Reusing existing event
    }

    function executeEmergencyWithdrawal() public {
        // Only the owner can execute emergency withdrawal
        require(msg.sender == owner);
        // Must have been requested first
        require(emergencyWithdrawalRequested == true);
        // Check if enough time has passed (vulnerable to timestamp manipulation)
        require(block.timestamp >= emergencyWithdrawalTimestamp + EMERGENCY_DELAY);
        // Reset the emergency state
        emergencyWithdrawalRequested = false;
        emergencyWithdrawalTimestamp = 0;
        // Transfer all tokens back to owner
        uint tokensRemaining = getTokensRemaining();
        if (tokensRemaining > 0) {
            tokenWallet.transfer(owner, tokensRemaining);
        }
        // Transfer all ether to owner
        if (this.balance > 0) {
            owner.transfer(this.balance);
        }
    }

    function cancelEmergencyWithdrawal() public {
        // Only the owner can cancel
        require(msg.sender == owner);
        // Must have been requested first
        require(emergencyWithdrawalRequested == true);
        // Reset the emergency state
        emergencyWithdrawalRequested = false;
        emergencyWithdrawalTimestamp = 0;
    }
    // === END FALLBACK INJECTION ===

    // Constructor
    function VRCoinCrowdsale(address walletAddress) {
        owner = msg.sender;
        tokenWallet = ERC20Interface(walletAddress);
        require(tokenWallet.totalSupply() >= TOTAL_TOKENS_TO_DISTRIBUTE);
        require(tokenWallet.balanceOf(owner) >= TOTAL_TOKENS_TO_DISTRIBUTE);
        hasStarted = false;
        sale.start = 1521234001; // 00:00:01, March 05, 2018 UTC
        sale.end = 1525122001; // 00:00:01, Apl 30, 2018 UTC
        sale.priceInWei = (1 ether) / (exchangeRate * coinToTokenFactor); // 1 ETH = 750 VRCoin
        sale.tokenToDistibute = TOTAL_TOKENS_TO_DISTRIBUTE;
    }

    function updatePrice() {
        require(msg.sender == owner);
        sale.priceInWei = (1 ether) / (exchangeRate * coinToTokenFactor);
    }

    function setExchangeRate(uint256 _rate) {
        require(msg.sender == owner);
        exchangeRate = _rate;
    }

    function startSale() {
        require(msg.sender == owner);
        require(hasStarted == false);
        if (!tokenWallet.transferFrom(owner, this, sale.tokenToDistibute)) {
            revert();
        } else {
            Transfer(this, sale.tokenToDistibute);
        }
        require(tokenWallet.balanceOf(this) >= sale.tokenToDistibute);
        hasStarted = true;
        Start(block.timestamp);
    }

    function changeOwner(address newOwner) public {
        require(msg.sender == owner);
        owner = newOwner;
    }

    function changeTokenForSale(uint newAmount) public {
        require(msg.sender == owner);
        require(hasStarted == false);
        require(tokenWallet.totalSupply() >= newAmount);
        require(tokenWallet.balanceOf(owner) >= newAmount);
        sale.tokenToDistibute = newAmount;
    }

    function changePeriodTime(uint start, uint end) public {
        require(msg.sender == owner);
        require(hasStarted == false);
        require(start < end);
        sale.start = start;
        sale.end = end;
    }

    function withdrawTokensRemaining() public returns (bool) {
        require(msg.sender == owner);
        uint crowdsaleEnd = sale.end;
        require(block.timestamp > crowdsaleEnd);
        uint tokensRemaining = getTokensRemaining();
        return tokenWallet.transfer(owner, tokensRemaining);
    }

    function withdrawEtherRemaining() public returns (bool) {
        require(msg.sender == owner);
        owner.transfer(this.balance);
        return true;
    }

    function getTokensRemaining() public constant returns (uint256) {
        return tokenWallet.balanceOf(this);
    }

    function getTokensForContribution(uint weiContribution) public constant returns(uint tokenAmount, uint weiRemainder) {
        uint256 bonus = 0;
        uint crowdsaleEnd = sale.end;
        require(block.timestamp <= crowdsaleEnd);
        uint periodPriceInWei = sale.priceInWei;
        tokenAmount = weiContribution / periodPriceInWei;
        if (block.timestamp < 1521234001) {
            bonus = tokenAmount * 20 / 100;
        } else if (block.timestamp < 1521925201) {
            bonus = tokenAmount * 15 / 100;
        } else {
            bonus = tokenAmount * 10 / 100;
        }
        tokenAmount = tokenAmount + bonus;
        weiRemainder = weiContribution % periodPriceInWei;
    }

    function contribute() public payable {
        require(hasStarted == true);
        var (tokenAmount, weiRemainder) = getTokensForContribution(msg.value);
        require(tokenAmount > 0);
        require(weiRemainder <= msg.value);
        uint tokensRemaining = getTokensRemaining();
        require(tokensRemaining >= tokenAmount);
        if (!tokenWallet.transfer(msg.sender, tokenAmount)) {
            revert();
        }
        msg.sender.transfer(weiRemainder);
        uint actualContribution = msg.value - weiRemainder;
        Contribution(msg.sender, actualContribution, tokenAmount);
    }

    function() payable {
        contribute();
    }
}
