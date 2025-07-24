/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering the external call to occur AFTER state updates in depositHelper(). This creates a window where an attacker can exploit the updated state through reentrancy. The vulnerability requires multiple transactions to build up accumulated state (stakes, investments, dividends) that can then be manipulated through carefully timed reentrant calls during the referral transfer.
 * 
 * **Specific Changes Made:**
 * 1. **Reordered Operations**: Moved `depositHelper(depostAmountAfterReferralFee)` to execute BEFORE the external `referralAddress.transfer(referralCommission)` call
 * 2. **State Update Before External Call**: This violates the checks-effects-interactions pattern by updating critical state variables (investment, stake, totalStake, dividendDebit) before the external call
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious referrer contract with a fallback function that can re-enter the deposit function
 * 2. **Accumulation Phase (Transactions 2-N)**: Victim makes multiple legitimate deposits, building up their investment[msg.sender], stake[msg.sender], and accumulated dividends
 * 3. **Exploitation Phase (Transaction N+1)**: Victim makes a deposit with the attacker's referrer address
 * 4. **Reentrancy Attack**: During the referral transfer, the attacker's fallback function re-enters deposit() multiple times, each time seeing the UPDATED state from step 3 but being able to manipulate it further before the original transaction completes
 * 5. **State Manipulation**: Each reentrant call can access and modify the updated stake and investment values, allowing the attacker to artificially inflate their position or drain the contract
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the accumulated state from previous legitimate deposits
 * - Without prior state accumulation, there would be minimal value to extract
 * - The attack becomes more profitable as the victim's stake and investment grow over time
 * - The totalStake variable needs to have substantial value for the mathematical manipulation to be worthwhile
 * - The dividend calculations depend on historical state that builds up across multiple transactions
 * 
 * **Realistic Attack Vector:**
 * A malicious referrer could wait for users to build up significant stakes through multiple deposits, then exploit the timing window during referral payouts to manipulate the contract's accounting system and extract disproportionate value.
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

    function ProofOfStableCoin() public {
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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Amount after deduct the referral commission - 5%
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    uint256 depostAmountAfterReferralFee = msg.value - referralCommission;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Push 95% of the deposit amount to depositHelper method BEFORE external call
        depositHelper(depostAmountAfterReferralFee);    
        
        // Transfer the 5% commission to the referral address AFTER state updates
	    referralAddress.transfer(referralCommission);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
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