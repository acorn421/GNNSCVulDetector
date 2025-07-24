/*
 * ===== SmartInject Injection Details =====
 * Function      : reinvest
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a sophisticated timestamp dependence vulnerability that requires multiple transactions to exploit effectively. The vulnerability introduces:
 * 
 * 1. **Time-based bonus accumulation**: Uses `firstReinvestTime` to track when a user first reinvested and calculates cumulative bonuses based on total time elapsed. This creates a stateful vulnerability where the bonus grows over time and across multiple reinvestments.
 * 
 * 2. **Block-based multiplier manipulation**: Introduces a `blockMultiplier` that depends on `block.number % 10`, allowing miners to manipulate block numbers to maximize bonuses across multiple reinvestment cycles.
 * 
 * 3. **Timestamp-dependent penalty system**: Implements a penalty for quick consecutive reinvestments using `lastReinvestTime`, which can be bypassed through timestamp manipulation in sequential transactions.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: User calls reinvest() for the first time, setting `firstReinvestTime[msg.sender] = now`
 * - **Wait/Mine**: Attacker (if they're a miner) can manipulate subsequent block timestamps and numbers
 * - **Transaction 2+**: User calls reinvest() again, now benefiting from accumulated time bonuses and block multipliers
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state persistence across transactions (`firstReinvestTime`, `lastReinvestTime`)
 * - The time-based bonus only applies after the first reinvestment establishes the baseline time
 * - The block multiplier can be optimized across multiple blocks/transactions
 * - The penalty system creates different exploitation paths depending on transaction timing sequences
 * 
 * **Exploitation Scenarios:**
 * 1. **Miner Manipulation**: A miner can reinvest, then manipulate subsequent block timestamps to maximize `totalTimeSinceFirst` and choose favorable `block.number` values for the multiplier
 * 2. **Sequential Timing**: Users can exploit the penalty system by timing their reinvestments to avoid penalties while maximizing time-based bonuses
 * 3. **Compound Exploitation**: The bonus compounds over multiple reinvestments, making the vulnerability more profitable with each subsequent transaction
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world timestamp dependence issues where miners can manipulate block properties to their advantage across multiple transactions.
 */
pragma solidity ^0.4.24;

/**
*
WaitOrReinvest HYIP strategy:
Withdraw dividends will reduce investments.
Reinvest dividends will increase investments.
50% dividends per day.
*/
contract WaitOrReinvest{
    
    using SafeMath for uint256;

    mapping(address => uint256) investments;
    mapping(address => uint256) joined;
    mapping(address => address) referrer;
    // ==== Added mappings for reinvestment timestamps ====
    mapping(address => uint256) public lastReinvestTime;
    mapping(address => uint256) public firstReinvestTime;

    uint256 public stepUp = 50; //50% per day
    address public ownerWallet;

    event Invest(address investor, uint256 amount);
    event Withdraw(address investor, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    /**
     * @dev Сonstructor Sets the original roles of the contract 
     */
    
    constructor() public {
        ownerWallet = msg.sender;
    }

    /**
     * @dev Modifiers
     */
    
    modifier onlyOwner() {
        require(msg.sender == ownerWallet);
        _;
    }

    /**
     * @dev Allows current owner to transfer control of the contract to a newOwner.
     * @param newOwnerWallet The address to transfer ownership to.
     */
    function transferOwnership(address newOwnerWallet) public onlyOwner {
        require(newOwnerWallet != address(0));
        emit OwnershipTransferred(ownerWallet, newOwnerWallet);
        ownerWallet = newOwnerWallet;
    }

    /**
     * @dev Investments
     */
 	
    function () public payable {
		invest(address(0));
	}
	
    function invest(address _ref) public payable {
        require(msg.value >= 0);
        if (investments[msg.sender] > 0){
            reinvest(); 
        }
        investments[msg.sender] = investments[msg.sender].add(msg.value);
        joined[msg.sender] = now;
		
		uint256 dfFee = msg.value.div(100).mul(5); //dev or ref fee
        ownerWallet.transfer(dfFee);
		
		
		if (referrer[msg.sender] == address(0) && address(_ref) > 0 && address(_ref) != msg.sender)
			referrer[msg.sender] = _ref;
		
		address ref = referrer[msg.sender];	
        if (ref > 0 ) 
			ref.transfer(dfFee); // bounty program
		
        emit Invest(msg.sender, msg.value);
    }
	
    function reinvest() public {
		require(investments[msg.sender] > 0);
		require((now - joined[msg.sender]) > 5);
		
		uint256 balance = getDivsBalance(msg.sender);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Introduce time-based bonus that accumulates across multiple reinvestments
		uint256 timeBonus = 0;
		uint256 timeSinceJoined = now.sub(joined[msg.sender]);
		
		// Store timestamp of first reinvestment for bonus calculation
		if (firstReinvestTime[msg.sender] == 0) {
			firstReinvestTime[msg.sender] = now;
		}
		
		// Calculate cumulative bonus based on total time since first reinvestment
		uint256 totalTimeSinceFirst = now.sub(firstReinvestTime[msg.sender]);
		if (totalTimeSinceFirst > 3600) { // After 1 hour
			// Bonus increases with each reinvestment cycle - miners can manipulate this
			timeBonus = balance.mul(totalTimeSinceFirst).div(86400).div(20); // Up to 5% bonus per day
			
			// Additional block-based multiplier that can be manipulated
			uint256 blockMultiplier = (block.number % 10) + 1; // 1-10x multiplier
			timeBonus = timeBonus.mul(blockMultiplier).div(5); // Average 2x multiplier
		}
		
		// Apply time-based penalty for quick consecutive reinvestments
		if (lastReinvestTime[msg.sender] > 0 && (now - lastReinvestTime[msg.sender]) < 300) {
			// Penalty reduces with each quick reinvestment - exploitable by timestamp manipulation
			uint256 penalty = balance.div(100).mul(2); // 2% penalty
			balance = balance.sub(penalty);
		}
		
		balance = balance.add(timeBonus);
		lastReinvestTime[msg.sender] = now;
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		
		uint256 dfFee = balance.div(100).mul(5); //dev or ref fee
		
		if (address(this).balance > dfFee) {
			address ref = referrer[msg.sender];	 
			if (ref != address(0))
				ref.transfer(dfFee); // bounty program
			else 
				ownerWallet.transfer(dfFee); // or dev fee
			balance = balance.sub(dfFee); 
		}
			
		investments[msg.sender] += balance;
		joined[msg.sender] = now;
	}

    /**
    * @dev Evaluate current balance
    * @param _address Address of investor
    */
    function getDivsBalance(address _address) view public returns (uint256) {
        uint256 secondsCount = now.sub(joined[_address]);
        uint256 percentDivs = investments[_address].mul(stepUp).div(100);
        uint256 dividends = percentDivs.mul(secondsCount).div(86400);

        return dividends;
    }

    /**
    * @dev Withdraw dividends from contract
    */
    function withdraw() public returns (bool){
        require(joined[msg.sender] > 0);
        uint256 balance = getDivsBalance(msg.sender);
        if (address(this).balance > balance){
            if (balance > 0){
				joined[msg.sender]=now;
                msg.sender.transfer(balance);
				
				if (investments[msg.sender] > balance)
					investments[msg.sender] = SafeMath.sub(investments[msg.sender],balance);
				else 
					investments[msg.sender] = 0;
					
                emit Withdraw(msg.sender, balance);
            }
            return true;
        } else {
            return false;
        }
    }
    

    /**
    * @dev Gets balance of the sender address.
    * @return An uint256 representing the amount owned by the msg.sender.
    */
    function checkDivsBalance() public view returns (uint256) {
        return getDivsBalance(msg.sender);
    }


    /**
    * @dev Gets investments of the specified address.
    * @param _investor The address to query the the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function checkInvestments(address _investor) public view returns (uint256) {
        return investments[_investor];
    }

    
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
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
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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