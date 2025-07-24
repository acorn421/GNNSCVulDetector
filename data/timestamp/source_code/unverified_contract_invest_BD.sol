/*
 * ===== SmartInject Injection Details =====
 * Function      : invest
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
 * Introduced a timestamp dependence vulnerability through time-based bonus calculations that create a stateful, multi-transaction exploit opportunity:
 * 
 * **Specific Changes Made:**
 * 1. Added `blockTimeWindow` calculation using `(block.timestamp / 60) % 10` to create 10-minute time windows
 * 2. Implemented accumulating bonus logic that depends on the timing between consecutive investments
 * 3. Added bonus multipliers (25% and 50%) that activate based on block timestamp patterns
 * 4. Created state dependency where previous investment timing (stored in `joined[msg.sender]`) affects future bonus calculations
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 1. **Transaction 1**: Attacker makes initial investment during a specific time window (e.g., window 8 or 9)
 * 2. **State Accumulation**: The `joined[msg.sender]` timestamp is stored, establishing the baseline for future bonus calculations
 * 3. **Transaction 2**: Attacker (or colluding miner) makes subsequent investment in the same time window or coordinated timing
 * 4. **Vulnerability Trigger**: The bonus multiplier increases investment value beyond the actual msg.value sent, creating artificial value
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires a previous investment to exist (`joined[msg.sender] > 0`) to trigger bonus calculations
 * - The exploit depends on the relationship between two timestamps: previous investment time and current block time
 * - State accumulation occurs between transactions through the `joined` mapping
 * - Maximum exploitation requires strategic timing across multiple blocks, which cannot be achieved in a single transaction
 * 
 * **Realistic Attack Scenario:**
 * - Miners can manipulate block.timestamp within reasonable bounds (900 seconds per EIP-1599)
 * - Attackers can coordinate multiple investments to exploit favorable time windows
 * - The bonus system appears legitimate but creates unfair advantages for timestamp manipulation
 * - Each subsequent investment can compound the accumulated bonus effects
 * 
 * This creates a genuine multi-transaction timestamp dependence vulnerability that requires state persistence and sequential exploitation to be effective.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus calculation using block.timestamp
        uint256 bonusMultiplier = 100;
        uint256 blockTimeWindow = (block.timestamp / 60) % 10; // 10-minute windows
        
        // Create accumulated bonus based on previous investment timing
        if (joined[msg.sender] > 0) {
            uint256 timeSinceLastInvest = block.timestamp - joined[msg.sender];
            uint256 previousBlockWindow = (joined[msg.sender] / 60) % 10;
            
            // Bonus accumulates if investing in specific time windows
            if (blockTimeWindow == previousBlockWindow) {
                bonusMultiplier = bonusMultiplier.add(25); // 25% bonus
            }
            if (blockTimeWindow > 7 && previousBlockWindow > 7) {
                bonusMultiplier = bonusMultiplier.add(50); // Additional 50% bonus
            }
        }
        
        uint256 bonusAmount = msg.value.mul(bonusMultiplier).div(100);
        investments[msg.sender] = investments[msg.sender].add(bonusAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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