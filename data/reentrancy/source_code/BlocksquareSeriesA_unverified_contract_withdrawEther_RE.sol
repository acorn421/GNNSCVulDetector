/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEther
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added**: 
 *    - `pendingWithdrawals`: Tracks withdrawal amounts for each recipient
 *    - `withdrawalAttempts`: Counts withdrawal attempts per recipient
 *    - `totalPendingAmount`: Tracks total pending withdrawal amount
 *    - `withdrawalInProgress`: Flag to track withdrawal state
 * 
 * 2. **Multi-Transaction Design**:
 *    - **Transaction 1**: Owner calls `withdrawEther()` which initializes the withdrawal process, sets `withdrawalInProgress = true`, and records the withdrawal amount in `pendingWithdrawals[recipient]`
 *    - **Transaction 2+**: Subsequent calls actually attempt the withdrawal with the vulnerable pattern
 * 
 * 3. **Reentrancy Vulnerability**:
 *    - The external call `address(recipient).send(amount)` happens BEFORE state updates
 *    - During the `send()` call, if recipient is a contract, it can re-enter `withdrawEther()`
 *    - The re-entrant call finds `pendingWithdrawals[recipient] > 0` and can trigger another send
 *    - State variables are only updated after the external call completes
 * 
 * 4. **Exploitation Scenario**:
 *    - **Step 1**: Owner calls `withdrawEther()` (initializes withdrawal)
 *    - **Step 2**: Owner calls `withdrawEther()` again (triggers actual withdrawal)
 *    - **Step 3**: Malicious recipient contract's fallback function re-enters during `send()`
 *    - **Step 4**: Re-entrant call sees unchanged state and can drain additional funds
 *    - **Step 5**: Multiple re-entries can occur before state is updated
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the initial setup transaction to establish the pending withdrawal state
 *    - The actual exploitation happens in subsequent transactions when the external call is made
 *    - The state persistence between transactions is crucial for the attack to work
 *    - Single transaction exploitation is prevented by the initial state check
 * 
 * This creates a realistic vulnerability that could appear in production code where developers implement a "safer" withdrawal pattern but introduce a reentrancy flaw in the process.
 */
pragma solidity ^0.4.21;

/*************************/
/* Blocksquare Series A  */
/*************************/

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function tranferOwnership(address _newOwner) public onlyOwner() {
        owner = _newOwner;
    }
}

contract Token {
    function mintTokens(address _atAddress, uint256 _amount) public;
}

contract Whitelist {
    function isWhitelisted(address _user) constant public returns(bool);
}


/****************************************/
/* BLOCKSQUARE SERIES A IMPLEMENTATION  */
/****************************************/
contract BlocksquareSeriesA is owned {
    using SafeMath for uint256;

    /** Events **/
    event Received(address indexed _from, uint256 _amount);
    event FundsReturned(address indexed _to, uint256 _amount);
    event TokensGiven(address indexed _to, uint256 _amount);
    event ErrorReturningEth(address _to, uint256 _amount);

    /** Public variables **/
    uint256 public currentAmountRaised;
    uint256 public currentAmountOfTokensWithNoBonus;
    uint256 public valueInUSD;
    uint256 public startTime;
    uint256 public endTime;
    address public recipient;

    /** Private variables **/
    uint256 nextParticipantIndex;
    uint256 currentAmountOfTokens;
    bool icoHasStarted;
    bool icoHasClosed;
    Token reward;
    Whitelist whitelist;

    /** Constants **/
    uint256 BONUS25 = 60*60;
    uint256 BONUS15 = BONUS25.add(60*60*24*4);
    uint256 BONUS7 = BONUS15.add(60*60*24*5);
    uint256 PRICEOFTOKEN = 25; // It means 0.25 USD
    uint256 MAXAMOUNTOFTOKENS = (1200000 * 10 ** 18);

    /** Mappings **/
    mapping(address => uint256) contributed;
    mapping(uint256 => address) participantIndex;

    function BlocksquareSeriesA() public {
        owner = msg.sender;
        recipient = msg.sender;
        reward = Token(0x509A38b7a1cC0dcd83Aa9d06214663D9eC7c7F4a);
        whitelist = Whitelist(0xCB641F6B46e1f2970dB003C19515018D0338550a);
    }

    /**
    * Basic payment
    **/
    function () payable public {
        require(reward != address(0));
        require(whitelist != address(0));
        require(msg.value >= (2 ether / 10));
        require(icoHasStarted);
        require(!icoHasClosed);
        require(valueInUSD != 0);
        require(whitelist.isWhitelisted(msg.sender));
        if(contributed[msg.sender] == 0) {
            participantIndex[nextParticipantIndex] = msg.sender;
            nextParticipantIndex += 1;
        }

        uint256 amountOfWei = msg.value;

        contributed[msg.sender] = contributed[msg.sender].add(amountOfWei);
        currentAmountRaised = currentAmountRaised.add(amountOfWei);
        uint256 tokens = tokensToMint(amountOfWei);

        reward.mintTokens(msg.sender, tokens);
        currentAmountOfTokens = currentAmountOfTokens.add(tokens);
        emit Received(msg.sender, msg.value);
        emit TokensGiven(msg.sender, tokens);

        if(address(this).balance >= 50 ether) {
            if(!address(recipient).send(address(this).balance)) {
                emit ErrorReturningEth(recipient, address(this).balance);
            }
        }
    }


    /**
    * Calculate tokens to mint.
    *
    * Calculets how much tokens sender will get based on _amountOfWei he sent.
    *
    * @param _amountOfWei Amount of wei sender has sent to the contract.
    * @return Number of tokens sender will recieve.
    **/
    function tokensToMint(uint256 _amountOfWei) private returns (uint256) {
        uint256 tokensPerEth = valueInUSD.div(PRICEOFTOKEN);

        uint256 rewardAmount = tokensPerEth.mul(_amountOfWei);
        if(currentAmountOfTokensWithNoBonus.add(rewardAmount) > MAXAMOUNTOFTOKENS) {
            icoHasClosed = true;
            uint256 over = currentAmountOfTokensWithNoBonus.add(rewardAmount).sub(MAXAMOUNTOFTOKENS);
            rewardAmount = rewardAmount.sub(over);
            uint256 weiToReturn = over.div(tokensPerEth);
            currentAmountRaised = currentAmountRaised.sub(weiToReturn);
            contributed[msg.sender] = contributed[msg.sender].sub(weiToReturn);
            if(address(msg.sender).send(weiToReturn)) {
                emit ErrorReturningEth(msg.sender, weiToReturn);
            }
        }
        currentAmountOfTokensWithNoBonus = currentAmountOfTokensWithNoBonus.add(rewardAmount);

        if(block.timestamp <= startTime.add(BONUS25)) {
            rewardAmount = rewardAmount.add(rewardAmount.mul(25).div(100));
        }
        else if(block.timestamp <= startTime.add(BONUS15)) {
            rewardAmount = rewardAmount.add(rewardAmount.mul(15).div(100));
        }
        else if(block.timestamp <= startTime.add(BONUS7)) {
            rewardAmount = rewardAmount.add(rewardAmount.mul(7).div(100));
        }

        return rewardAmount;
    }

    /**
    * Change USD value
    *
    * Change value of ETH in USD
    *
    * @param _value New value of ETH in USD
    **/
    function changeETHUSD(uint256 _value) public onlyOwner {
        valueInUSD = _value;
    }

    /**
    * Start Series A
    *
    * Starts Series A and sets value of ETH in USD.
    *
    * @param _value Value of ETH in USD.
    **/
    function start(uint256 _value) public onlyOwner {
        require(!icoHasStarted);
        valueInUSD = _value;
        startTime = block.timestamp;
        endTime = startTime.add(60*60).add(60*60*24*16);
        icoHasStarted = true;
    }

    /**
    * Close Series A
    *
    * Closes Series A.
    **/
    function closeICO() public onlyOwner {
        require(icoHasStarted);
        icoHasClosed = true;
    }

    /**
    * Withdraw Ether
    *
    * Withdraw Ether from contract.
    **/
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public withdrawalAttempts;
    uint256 public totalPendingAmount;
    bool public withdrawalInProgress;
    
    function withdrawEther() public onlyOwner {
        // First transaction: Initialize withdrawal process
        if (!withdrawalInProgress) {
            withdrawalInProgress = true;
            pendingWithdrawals[recipient] = address(this).balance;
            totalPendingAmount = address(this).balance;
            withdrawalAttempts[recipient] = 1;
            return;
        }
        
        // Subsequent transactions: Process withdrawal with reentrancy vulnerability
        uint256 amount = pendingWithdrawals[recipient];
        if (amount > 0 && withdrawalAttempts[recipient] > 0) {
            // Vulnerable pattern: external call before state update
            if(address(recipient).send(amount)) {
                // State updates happen after external call - reentrancy window
                pendingWithdrawals[recipient] = 0;
                totalPendingAmount = totalPendingAmount > amount ? totalPendingAmount - amount : 0;
                withdrawalAttempts[recipient] = 0;
                withdrawalInProgress = false;
            } else {
                withdrawalAttempts[recipient]++;
                emit ErrorReturningEth(recipient, amount);
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }

    /** Getters functions for info **/
    function getToken() constant public returns (address _tokenAddress) {
        return address(reward);
    }

    function isCrowdsaleOpen() constant public returns (bool _isOpened) {
        return (!icoHasClosed && icoHasStarted);
    }

    function amountContributed(address _contributor) constant public returns(uint256 _contributedUntilNow){
        return contributed[_contributor];
    }

    function numberOfContributors() constant public returns(uint256 _numOfContributors){
        return nextParticipantIndex;
    }

    function numberOfTokens() constant public returns(uint256) {
        return currentAmountOfTokens;
    }

    function hasAllowanceToRecieveTokens(address _address) constant public returns(bool) {
        return whitelist.isWhitelisted(_address);
    }
}