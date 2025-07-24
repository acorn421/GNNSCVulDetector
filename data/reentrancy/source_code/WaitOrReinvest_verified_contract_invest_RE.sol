/*
 * ===== SmartInject Injection Details =====
 * Function      : invest
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Callback**: When setting a referrer, the function now makes an external call to the referrer contract using `onReferralSet(address,uint256)` callback, passing the original investment amount.
 * 
 * 2. **Vulnerable State Update Order**: The critical state updates (`investments[msg.sender]` and `joined[msg.sender]`) are moved to occur AFTER the external callback, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker invests initial amount (e.g., 1 ETH) to establish investment state
 *    - **Transaction 2**: Attacker creates malicious referrer contract and calls invest() again with the malicious contract as referrer
 *    - **Transaction 3**: During the callback, the malicious referrer can re-enter invest() while the state still shows the old investment amount, potentially manipulating the investment accounting
 * 
 * 4. **Stateful Nature**: The vulnerability depends on:
 *    - Previous investment state (`originalInvestment` from earlier transactions)
 *    - Referrer relationships established across multiple calls
 *    - Accumulated investment amounts that persist between transactions
 * 
 * 5. **Realistic Attack Vector**: The callback mechanism appears legitimate (notifying referrers of new referrals) but creates a reentrancy window where an attacker can manipulate the investment accounting by re-entering during the callback before state updates are finalized.
 * 
 * The vulnerability requires multiple transactions to build up the necessary state and cannot be exploited in a single atomic transaction, making it a sophisticated stateful reentrancy attack.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original investment amount for callback
        uint256 originalInvestment = investments[msg.sender];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (investments[msg.sender] > 0){
            reinvest(); 
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        uint256 dfFee = msg.value.div(100).mul(5); //dev or ref fee
        ownerWallet.transfer(dfFee);
		
        // Set referrer with callback notification before state update
        if (referrer[msg.sender] == address(0) && _ref != address(0) && _ref != msg.sender) {
            referrer[msg.sender] = _ref;
            
            // Notify referrer with callback before investment state is updated
            // In Solidity 0.4.24, there is no address.code property.
            // To check if _ref is a contract, we use extcodesize:
            uint256 size;
            assembly { size := extcodesize(_ref) }
            if (size > 0) {
                _ref.call(abi.encodeWithSignature("onReferralSet(address,uint256)", msg.sender, originalInvestment));
                // Continue execution regardless of callback success
            }
        }
		
		// State updates happen after external calls - vulnerable to reentrancy
        investments[msg.sender] = investments[msg.sender].add(msg.value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        joined[msg.sender] = now;
	
		address ref = referrer[msg.sender];	
        if (ref != address(0) ) 
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
