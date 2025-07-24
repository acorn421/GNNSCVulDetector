/*
 * ===== SmartInject Injection Details =====
 * Function      : enableEmergencyWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability implements a stateful, multi-transaction reentrancy attack. The vulnerability requires two separate transactions: (1) enableEmergencyWithdrawal() to set up the withdrawal state, and (2) executeEmergencyWithdrawal() to execute the vulnerable withdrawal. The second function uses call.value() before updating state variables, making it vulnerable to reentrancy attacks where an attacker can repeatedly call executeEmergencyWithdrawal() to drain more funds than they're entitled to. The state persistence between transactions (emergencyWithdrawalEnabled, emergencyWithdrawalAmount, emergencyWithdrawalTimestamp) is crucial for the attack to work.
 */
pragma solidity ^0.4.21;

contract ProofOfStableCoin {
    using SafeMath for uint256;

    event Deposit(address user, uint amount);
    event Withdraw(address user, uint amount);
    event Claim(address user, uint dividends);
    event Reinvest(address user, uint dividends);

    address owner;
    mapping(address => bool) preauthorized;
    bool gameStarted;

    uint constant depositTaxDivisor = 3;
    uint constant withdrawalTaxDivisor = 3;

    mapping(address => uint) public investment;

    mapping(address => uint) public stake;
    uint public totalStake;
    uint stakeValue;

    mapping(address => uint) dividendCredit;
    mapping(address => uint) dividendDebit;

    // === FALLBACK INJECTION: Reentrancy ===
    // Emergency withdrawal mechanism state
    mapping(address => bool) public emergencyWithdrawalEnabled;
    mapping(address => uint) public emergencyWithdrawalAmount;
    uint public emergencyWithdrawalDelay = 1 hours;
    mapping(address => uint) public emergencyWithdrawalTimestamp;
    // === END FALLBACK INJECTION ===

    function ProofOfStableCoin() public {
        owner = msg.sender;
        preauthorized[owner] = true;
    }

    // === FALLBACK INJECTION FUNCTIONS ===
    // Step 1: Enable emergency withdrawal (sets state for future transactions)
    function enableEmergencyWithdrawal() public {
        require(investment[msg.sender] > 0, "No investment found");
        require(!emergencyWithdrawalEnabled[msg.sender], "Already enabled");
        emergencyWithdrawalEnabled[msg.sender] = true;
        emergencyWithdrawalAmount[msg.sender] = investment[msg.sender];
        emergencyWithdrawalTimestamp[msg.sender] = now;
    }
    
    // Step 2: Execute emergency withdrawal (vulnerable to reentrancy)
    function executeEmergencyWithdrawal() public {
        require(emergencyWithdrawalEnabled[msg.sender], "Emergency withdrawal not enabled");
        require(now >= emergencyWithdrawalTimestamp[msg.sender] + emergencyWithdrawalDelay, "Time delay not met");
        require(emergencyWithdrawalAmount[msg.sender] > 0, "No amount to withdraw");
        uint withdrawAmount = emergencyWithdrawalAmount[msg.sender];
        // Vulnerable: External call before state update
        msg.sender.call.value(withdrawAmount)();
        // State updates after external call - vulnerable to reentrancy
        emergencyWithdrawalEnabled[msg.sender] = false;
        emergencyWithdrawalAmount[msg.sender] = 0;
        investment[msg.sender] = 0;
        // Update stake proportionally
        uint stakeDecrement = stake[msg.sender];
        stake[msg.sender] = 0;
        totalStake = totalStake.sub(stakeDecrement);
    }
    // === END FALLBACK INJECTION FUNCTIONS ===

    function preauthorize(address _user) public {
        require(msg.sender == owner);
        preauthorized[_user] = true;
    }

    function startGame() public {
        require(msg.sender == owner);
        gameStarted = true;
    }

    function depositHelper(uint _amount) private {
        uint _tax = _amount.div(depositTaxDivisor);
        uint _amountAfterTax = _amount.sub(_tax);
        if (totalStake > 0)
            stakeValue = stakeValue.add(_tax.div(totalStake));
        uint _stakeIncrement = sqrt(totalStake.mul(totalStake).add(_amountAfterTax)).sub(totalStake);
        investment[msg.sender] = investment[msg.sender].add(_amountAfterTax);
        stake[msg.sender] = stake[msg.sender].add(_stakeIncrement);
        totalStake = totalStake.add(_stakeIncrement);
        dividendDebit[msg.sender] = dividendDebit[msg.sender].add(_stakeIncrement.mul(stakeValue));
    }

    function deposit(uint _amount, address _referrer) public payable {
        require(preauthorized[msg.sender] || gameStarted);
        uint256 _depositAmount = _amount;
        address referralAddress = _referrer;
        address uninitializedAddress = address(0);
       
        // If the referral address is defined then deduct 5% and transfer to the referral address otherwise skip it
        if(_referrer != uninitializedAddress){
         
        // Calculate the 5% of referral commission
        uint256 referralCommission = (_depositAmount / 20); // => 5%
        // Transfer the 5% commission to the referral address
        referralAddress.transfer(referralCommission);
        
        // Amount after deduct the referral commission - 5%
        uint256 depostAmountAfterReferralFee = msg.value - referralCommission;
        
        // Push 95% of the deposit amount to depositHelper method
        depositHelper(depostAmountAfterReferralFee);    
        
        }
        
        else {
            
        // Push 100% of the deposit amount to depositHelper method if there is no referral address
        depositHelper(_depositAmount);
    
        }
    
        emit Deposit(msg.sender, msg.value);
    
    }

    function withdraw(uint _amount) public {
        require(_amount > 0);
        require(_amount <= investment[msg.sender]);
        uint _tax = _amount.div(withdrawalTaxDivisor);
        uint _amountAfterTax = _amount.sub(_tax);
        uint _stakeDecrement = stake[msg.sender].mul(_amount).div(investment[msg.sender]);
        uint _dividendCredit = _stakeDecrement.mul(stakeValue);
        investment[msg.sender] = investment[msg.sender].sub(_amount);
        stake[msg.sender] = stake[msg.sender].sub(_stakeDecrement);
        totalStake = totalStake.sub(_stakeDecrement);
        if (totalStake > 0)
            stakeValue = stakeValue.add(_tax.div(totalStake));
        dividendCredit[msg.sender] = dividendCredit[msg.sender].add(_dividendCredit);
        uint _creditDebitCancellation = min(dividendCredit[msg.sender], dividendDebit[msg.sender]);
        dividendCredit[msg.sender] = dividendCredit[msg.sender].sub(_creditDebitCancellation);
        dividendDebit[msg.sender] = dividendDebit[msg.sender].sub(_creditDebitCancellation);
        msg.sender.transfer(_amountAfterTax);
        emit Withdraw(msg.sender, _amount);
    }

    function claimHelper() private returns(uint) {
        uint _dividendsForStake = stake[msg.sender].mul(stakeValue);
        uint _dividends = _dividendsForStake.add(dividendCredit[msg.sender]).sub(dividendDebit[msg.sender]);
        dividendCredit[msg.sender] = 0;
        dividendDebit[msg.sender] = _dividendsForStake;
        return _dividends;
    }

    function claim() public {
        uint _dividends = claimHelper();
        msg.sender.transfer(_dividends);
        emit Claim(msg.sender, _dividends);
    }

    function reinvest() public {
        uint _dividends = claimHelper();
        depositHelper(_dividends);
        emit Reinvest(msg.sender, _dividends);
    }

    function dividendsForUser(address _user) public view returns (uint) {
        return stake[_user].mul(stakeValue).add(dividendCredit[_user]).sub(dividendDebit[_user]);
    }

    function min(uint x, uint y) private pure returns (uint) {
        return x <= y ? x : y;
    }

    function sqrt(uint x) private pure returns (uint y) {
        uint z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

    /**
    * @dev Multiplies two numbers, throws on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;                                                                                                                                                                                       
        }
        uint256 c = a * b;                                                                                                                                                                                  
        assert(c / a == b);                                                                                                                                                                                 
        return c;                                                                                                                                                                                           
    }

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0                                                                                                                               
        // uint256 c = a / b;                                                                                                                                                                               
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold                                                                                                                       
        return a / b;                                                                                                                                                                                       
    }

    /**
    * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);                                                                                                                                                                                     
        return a - b;                                                                                                                                                                                       
    }

    /**
    * @dev Adds two numbers, throws on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;                                                                                                                                                                                  
        assert(c >= a);                                                                                                                                                                                     
        return c;                                                                                                                                                                                           
    }
}
