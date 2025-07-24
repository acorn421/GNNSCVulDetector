/*
 * ===== SmartInject Injection Details =====
 * Function      : addOwner
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner address after state updates but before event emission. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_owner.call(abi.encodeWithSignature("onOwnerAdded()"))` after state updates
 * 2. The call occurs after `isOwner[_owner] = true` and `owners.push(_owner)` but before `emit OwnerAddition(_owner)`
 * 3. Added a check for contract code existence to make the callback realistic
 * 4. Used low-level call to avoid reverting the entire transaction if callback fails
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract with `onOwnerAdded()` function
 * 2. **Transaction 2 (Initial Call)**: Legitimate owner calls `addOwner()` with the malicious contract address
 * 3. **During Transaction 2**: The malicious contract's `onOwnerAdded()` callback is triggered, allowing reentrancy
 * 4. **Reentrancy Exploitation**: The malicious contract can call other owner-restricted functions while having owner privileges but before the OwnerAddition event is emitted
 * 5. **State Persistence**: The owner status persists across transactions, enabling continued exploitation
 * 
 * **Why Multiple Transactions Are Required:**
 * - The malicious contract must be deployed first (Transaction 1)
 * - The actual exploitation occurs during the callback in Transaction 2
 * - The vulnerability relies on the persistent state change (`isOwner[_owner] = true`) that was made before the external call
 * - Subsequent transactions can leverage the accumulated owner state for further exploitation
 * - The vulnerability becomes more powerful with each successful owner addition, creating a stateful accumulation of privileged addresses
 * 
 * **Realistic Exploitation Scenarios:**
 * - Malicious contract could immediately call other owner functions during the callback
 * - Multiple malicious owners could be added in succession, each triggering callbacks
 * - The persistent owner state enables ongoing multi-transaction exploitation patterns
 * - Attackers could manipulate other contract functions that depend on owner status during the callback window
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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Notify the new owner about their addition with callback
		if (isContract(_owner)) {
			(bool success, ) = _owner.call(abi.encodeWithSignature("onOwnerAdded()"));
			// Continue regardless of callback success
		}
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		emit OwnerAddition(_owner);
	}
	
	// Helper to check if address is contract in Solidity 0.4.x
	function isContract(address _addr) internal view returns (bool) {
		uint256 size;
		assembly { size := extcodesize(_addr) }
		return size > 0;
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
		isOwner[_owner] = false;
		for (uint i = 0; i < owners.length - 1; i++)
			if (owners[i] == _owner) {
				owners[i] = owners[owners.length - 1];
				break;
			}
		owners.length -= 1;
		emit OwnerRemoval(_owner);
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
