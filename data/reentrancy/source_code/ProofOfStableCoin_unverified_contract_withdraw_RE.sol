/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by: 1) Adding a pendingWithdrawals mapping to track accumulated withdrawal state across transactions, 2) Moving the external transfer call before state updates, violating the Checks-Effects-Interactions pattern, 3) Creating a window where reentrant calls can manipulate the accumulated pending withdrawals state before the original call completes its state updates. This requires multiple transactions to exploit as the attacker must first accumulate pending withdrawals through legitimate calls, then exploit the reentrancy during the transfer to manipulate the accumulated state before it's cleared.
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

    // Added declaration for pendingWithdrawals to fix undeclared identifier error
    mapping(address => uint) pendingWithdrawals;

    constructor() public {
        owner = msg.sender;
        preauthorized[owner] = true;
    }

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending withdrawal tracking for multi-transaction processing
        pendingWithdrawals[msg.sender] = pendingWithdrawals[msg.sender].add(_amountAfterTax);
        
        // Perform external call BEFORE updating critical state variables
        msg.sender.transfer(_amountAfterTax);
        
        // State updates occur after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        investment[msg.sender] = investment[msg.sender].sub(_amount);
        stake[msg.sender] = stake[msg.sender].sub(_stakeDecrement);
        totalStake = totalStake.sub(_stakeDecrement);
        if (totalStake > 0)
            stakeValue = stakeValue.add(_tax.div(totalStake));
        dividendCredit[msg.sender] = dividendCredit[msg.sender].add(_dividendCredit);
        uint _creditDebitCancellation = min(dividendCredit[msg.sender], dividendDebit[msg.sender]);
        dividendCredit[msg.sender] = dividendCredit[msg.sender].sub(_creditDebitCancellation);
        dividendDebit[msg.sender] = dividendDebit[msg.sender].sub(_creditDebitCancellation);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending withdrawal only after all state updates
        pendingWithdrawals[msg.sender] = pendingWithdrawals[msg.sender].sub(_amountAfterTax);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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