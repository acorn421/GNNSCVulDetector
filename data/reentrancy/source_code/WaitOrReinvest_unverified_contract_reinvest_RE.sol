/*
 * ===== SmartInject Injection Details =====
 * Function      : reinvest
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Maintained External Call Position**: Kept the `ref.transfer(dfFee)` call before state updates, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **State Update Vulnerability**: The critical state updates (`investments[msg.sender] += balance` and `joined[msg.sender] = now`) occur after external calls, creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User calls `reinvest()` which calculates dividends based on current `joined[msg.sender]` timestamp
 *    - **Reentrancy**: Malicious referrer contract's fallback function calls back into `reinvest()` during the `ref.transfer(dfFee)` call
 *    - **Transaction 2+**: The reentrant call still sees the old `joined[msg.sender]` timestamp, allowing additional dividend extraction before state is updated
 *    - **State Persistence**: Each successful reentrancy call increases `investments[msg.sender]` while `joined[msg.sender]` remains outdated until the original call completes
 * 
 * 4. **Stateful Multi-Transaction Requirements**:
 *    - The vulnerability requires the contract to accumulate state across multiple reinvest calls
 *    - Each reentrant call can extract dividends based on the time elapsed since the original `joined[msg.sender]` timestamp
 *    - Multiple transactions are needed to drain significant funds as each call is limited by the dividend calculation and contract balance
 *    - The exploit becomes more profitable as more time passes between the original join time and the attack
 * 
 * 5. **Realistic Attack Vector**: A malicious user can set up a referrer contract that implements a fallback function to re-enter `reinvest()`, allowing them to extract dividends multiple times before the state is properly updated.
 * 
 * The vulnerability is not exploitable in a single transaction because the dividend calculation depends on time elapsed, and the accumulated state from previous investments makes subsequent reentrancy calls more profitable.
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
		
		uint256 dfFee = balance.div(100).mul(5); //dev or ref fee
		
		if (address(this).balance > dfFee) {
			address ref = referrer[msg.sender];	 
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			if (ref != address(0)) {
				// Vulnerable: External call before state update allows reentrancy
				ref.transfer(dfFee); // bounty program
			} else {
				ownerWallet.transfer(dfFee); // or dev fee
			}
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
			balance = balance.sub(dfFee); 
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Vulnerable: State updates occur after external calls
		// This allows reentrancy to exploit stale state across multiple transactions
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
