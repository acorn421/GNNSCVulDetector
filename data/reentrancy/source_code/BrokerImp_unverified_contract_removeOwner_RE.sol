/*
 * ===== SmartInject Injection Details =====
 * Function      : removeOwner
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the owner being removed BEFORE state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_owner.call(abi.encodeWithSignature("onOwnerRemoval()"))` before any state changes
 * 2. Added contract existence check with `_owner.code.length > 0` to make the callback realistic
 * 3. Positioned the callback at the beginning, creating a classic CEI (Checks-Effects-Interactions) pattern violation
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Malicious owner contract is deployed and added as legitimate owner
 * 2. **Transaction 2 (Trigger)**: Another owner calls `removeOwner()` on the malicious contract
 * 3. **Transaction 3+ (Exploit)**: During the callback in Transaction 2, the malicious contract:
 *    - Still has `isOwner[malicious_contract] = true` (state not yet modified)
 *    - Can call other owner-only functions like `addOwner()`, `changeCommission()`, etc.
 *    - Can manipulate contract state while having temporary owner privileges
 *    - Can even call `removeOwner()` on other legitimate owners
 * 
 * **Why Multi-Transaction is Required:**
 * - The attack requires prior setup of a malicious contract as an owner (Transaction 1)
 * - The malicious contract must implement `onOwnerRemoval()` to receive the callback
 * - During the callback, the contract can initiate additional transactions to other functions
 * - The vulnerability window only exists during the external call, requiring coordinated timing
 * - Full exploitation requires the malicious contract to abuse its still-valid owner status during the callback
 * 
 * **Stateful Nature:**
 * - The `isOwner` mapping and `owners` array represent persistent state
 * - The vulnerability depends on the temporal state where external call occurs before state updates
 * - Attack effects persist across transactions and can affect future contract operations
 * - The malicious contract can leave permanent changes (new owners, modified parameters) even after being removed
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions and stateful coordination to exploit effectively.
 */
pragma solidity ^0.4.21;
/**
 * Changes by https://www.docademic.com/
 */

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

/**
 * Changes by https://www.docademic.com/
 */

/**
 * @title MultiOwnable
 * @dev The MultiOwnable contract has multiple owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract MultiOwnable {
	
	address[] public owners;
	mapping(address => bool) public isOwner;
	
	event OwnerAddition(address indexed owner);
	event OwnerRemoval(address indexed owner);
	
	/**
	 * @dev The MultiOwnable constructor sets the original `owner` of the contract to the sender
	 * account.
	 */
	constructor() public {
		isOwner[msg.sender] = true;
		owners.push(msg.sender);
	}
	
	/**
   * @dev Throws if called by any account other than the owner.
   */
	modifier onlyOwner() {
		require(isOwner[msg.sender]);
		_;
	}
	
	/**
	 * @dev Throws if called by an owner.
	 */
	modifier ownerDoesNotExist(address _owner) {
		require(!isOwner[_owner]);
		_;
	}
	
	/**
	 * @dev Throws if called by any account other than the owner.
	 */
	modifier ownerExists(address _owner) {
		require(isOwner[_owner]);
		_;
	}
	
	/**
	 * @dev Throws if called with a null address.
	 */
	modifier notNull(address _address) {
		require(_address != 0);
		_;
	}
	
	/**
	 * @dev Allows to add a new owner. Transaction has to be sent by an owner.
	 * @param _owner Address of new owner.
	 */
	function addOwner(address _owner)
	public
	onlyOwner
	ownerDoesNotExist(_owner)
	notNull(_owner)
	{
		isOwner[_owner] = true;
		owners.push(_owner);
		emit OwnerAddition(_owner);
	}
	
	/**
	 * @dev Allows to remove an owner. Transaction has to be sent by wallet.
	 * @param _owner Address of owner.
	 */
	function removeOwner(address _owner)
	public
	onlyOwner
	ownerExists(_owner)
	{
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		// Notify the owner before removal - creates reentrancy window
		if (isContract(_owner)) {
			(bool success, ) = _owner.call(abi.encodeWithSignature("onOwnerRemoval()"));
			// Continue regardless of callback result
		}
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		isOwner[_owner] = false;
		for (uint i = 0; i < owners.length - 1; i++)
			if (owners[i] == _owner) {
				owners[i] = owners[owners.length - 1];
				break;
			}
		owners.length -= 1;
		emit OwnerRemoval(_owner);
	}
	
	// Helper function to determine if address is contract
	function isContract(address _addr) internal view returns (bool) {
		uint256 size;
		assembly { size := extcodesize(_addr) }
		return size > 0;
	}
	
}

contract DestroyableMultiOwner is MultiOwnable {
	/**
	 * @notice Allows to destroy the contract and return the tokens to the owner.
	 */
	function destroy() public onlyOwner {
		selfdestruct(owners[0]);
	}
}

interface Token {
	function transferFrom(address _from, address _to, uint256 _value) external returns (bool);
}

contract BrokerImp is DestroyableMultiOwner {
	using SafeMath for uint256;
	
	Token public token;
	uint256 public commission;
	address public broker;
	address public pool;
	uint256 public ethReward;
	mapping(address => bool) public ethSent;
	
	event CommissionChanged(uint256 _previousCommission, uint256 _commision);
	event EthRewardChanged(uint256 _previousEthReward, uint256 _ethReward);
	event BrokerChanged(address _previousBroker, address _broker);
	event PoolChanged(address _previousPool, address _pool);
	
	/**
	 * @dev Constructor.
	 * @param _token The token address
	 * @param _pool The pool of tokens address
	 * @param _commission The percentage of the commission 0-100
	 * @param _broker The broker address
	 * @param _ethReward The eth to send to the beneficiary of the reward only once in wei
	 */
	constructor(address _token, address _pool, uint256 _commission, address _broker, uint256 _ethReward) public {
		require(_token != address(0));
		token = Token(_token);
		pool = _pool;
		commission = _commission;
		broker = _broker;
		ethReward = _ethReward;
	}
	
	/**
	 * @dev Allows to fund the contract with ETH.
	 */
	function fund(uint256 amount) payable public {
		require(msg.value == amount);
	}
	
	/**
	 * @dev Allows the owner make a reward.
	 * @param _beneficiary the beneficiary address
	 * @param _value the tokens reward in wei
	 */
	function reward(address _beneficiary, uint256 _value) public onlyOwner returns (bool) {
		uint256 hundred = uint256(100);
		uint256 beneficiaryPart = hundred.sub(commission);
		uint256 total = (_value.div(beneficiaryPart)).mul(hundred);
		uint256 brokerCommission = total.sub(_value);
		if (!ethSent[_beneficiary]) {
			_beneficiary.transfer(ethReward);
			ethSent[_beneficiary] = true;
		}
		return (
		token.transferFrom(pool, broker, brokerCommission) &&
		token.transferFrom(pool, _beneficiary, _value)
		);
	}
	
	/**
	 * @dev Allows the owner to change the commission of the reward.
	 * @param _commission The percentage of the commission 0-100
	 */
	function changeCommission(uint256 _commission) public onlyOwner {
		emit CommissionChanged(commission, _commission);
		commission = _commission;
	}
	
	/**
	 * @dev Allows the owner to withdraw the balance of the tokens.
	 * @param _ethReward The eth reward to send to the beneficiary in wei
	 */
	function changeEthReward(uint256 _ethReward) public onlyOwner {
		emit EthRewardChanged(ethReward, _ethReward);
		ethReward = _ethReward;
	}
	
	/**
	 * @dev Allows the owner to change the broker.
	 * @param _broker The broker address
	 */
	function changeBroker(address _broker) public onlyOwner {
		emit BrokerChanged(broker, _broker);
		broker = _broker;
	}
	
	/**
	 * @dev Allows the owner to change the pool of tokens.
	 * @param _pool The pool address
	 */
	function changePool(address _pool) public onlyOwner {
		emit PoolChanged(pool, _pool);
		pool = _pool;
	}
}