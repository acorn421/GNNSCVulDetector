/*
 * ===== SmartInject Injection Details =====
 * Function      : tranferOwnership
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability by implementing a two-step ownership transfer process that relies on block.timestamp for timing validation. The vulnerability requires state variables (pendingOwner, ownershipTransferInitiated) to persist between transactions and creates a time window where miners can manipulate block.timestamp to either accelerate transfers or cause them to expire. The exploit requires multiple transactions: first to initiate the transfer, then a second within a specific time window to complete it.
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
    address public pendingOwner;
    uint256 public ownershipTransferInitiated;
    uint256 public startTime;

    function owned() public {
        owner = msg.sender;
        startTime = block.timestamp;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function tranferOwnership(address _newOwner) public onlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Check if this is during the deployment window (first 7 days)
        if (block.timestamp <= startTime + 7 days) {
            // During deployment window, allow immediate ownership transfer
            owner = _newOwner;
        } else {
            // After deployment window, require two-step process with time delay
            if (pendingOwner == address(0)) {
                // First transaction: initiate ownership transfer
                pendingOwner = _newOwner;
                ownershipTransferInitiated = block.timestamp;
            } else if (pendingOwner == _newOwner &&
                       block.timestamp >= ownershipTransferInitiated + 24 hours &&
                       block.timestamp <= ownershipTransferInitiated + 72 hours) {
                // Second transaction: complete ownership transfer within valid window
                owner = _newOwner;
                pendingOwner = address(0);
                ownershipTransferInitiated = 0;
            } else if (block.timestamp > ownershipTransferInitiated + 72 hours) {
                // Transfer window expired, reset pending transfer
                pendingOwner = address(0);
                ownershipTransferInitiated = 0;
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    //uint256 public startTime; // Already declared in owned
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
        startTime = block.timestamp;
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
    function withdrawEther() public onlyOwner {
        if(!address(recipient).send(address(this).balance)) {
            emit ErrorReturningEth(recipient, address(this).balance);
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
