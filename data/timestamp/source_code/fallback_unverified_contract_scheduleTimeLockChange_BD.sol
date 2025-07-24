/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimeLockChange
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction time-locked parameter change system. The vulnerability requires: 1) First transaction to schedule a change with scheduleTimeLockChange(), which stores a proposal with an unlock time based on block.timestamp. 2) Second transaction to execute the change with executeTimeLockChange(), which validates the time lock using block.timestamp. A malicious miner can manipulate timestamps to either delay execution beyond intended time or execute changes earlier than the intended delay period. The state persists between transactions through the timeLockProposals mapping, making this a stateful, multi-transaction vulnerability that cannot be exploited in a single call.
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
	function MultiOwnable() public {
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked parameter change system
    struct TimeLockProposal {
        uint256 proposedValue;
        uint256 unlockTime;
        bool executed;
        address proposer;
    }

    mapping(bytes32 => TimeLockProposal) public timeLockProposals;
    uint256 public constant TIME_LOCK_DELAY = 1 days;

    event TimeLockProposalCreated(bytes32 indexed proposalId, uint256 proposedValue, uint256 unlockTime);
    event TimeLockProposalExecuted(bytes32 indexed proposalId, uint256 newValue);
    // === END FALLBACK INJECTION ===
	
	/**
	 * @dev Constructor.
	 * @param _token The token address
	 * @param _pool The pool of tokens address
	 * @param _commission The percentage of the commission 0-100
	 * @param _broker The broker address
	 * @param _ethReward The eth to send to the beneficiary of the reward only once in wei
	 */
	function BrokerImp(address _token, address _pool, uint256 _commission, address _broker, uint256 _ethReward) public {
		require(_token != address(0));
		token = Token(_token);
		pool = _pool;
		commission = _commission;
		broker = _broker;
		ethReward = _ethReward;
	}
    /**
     * @dev Schedule a time-locked commission change
     * @param _newCommission The new commission percentage to be set after timelock
     */
    function scheduleTimeLockChange(uint256 _newCommission) public onlyOwner {
        require(_newCommission <= 100, "Commission cannot exceed 100%");
        bytes32 proposalId = keccak256(abi.encodePacked("commission", block.timestamp, msg.sender));
        // Vulnerable: Using block.timestamp for time calculations
        uint256 unlockTime = block.timestamp + TIME_LOCK_DELAY;
        timeLockProposals[proposalId] = TimeLockProposal({
            proposedValue: _newCommission,
            unlockTime: unlockTime,
            executed: false,
            proposer: msg.sender
        });
        emit TimeLockProposalCreated(proposalId, _newCommission, unlockTime);
    }
    /**
     * @dev Execute a time-locked commission change after the delay period
     * @param _proposalId The ID of the proposal to execute
     */
    function executeTimeLockChange(bytes32 _proposalId) public {
        TimeLockProposal storage proposal = timeLockProposals[_proposalId];
        require(proposal.proposer != address(0), "Proposal does not exist");
        require(!proposal.executed, "Proposal already executed");
        // Vulnerable: Relying on block.timestamp for time validation
        require(block.timestamp >= proposal.unlockTime, "Time lock period not expired");
        require(isOwner[msg.sender], "Only owners can execute proposals");
        proposal.executed = true;
        uint256 oldCommission = commission;
        commission = proposal.proposedValue;
        emit TimeLockProposalExecuted(_proposalId, proposal.proposedValue);
        emit CommissionChanged(oldCommission, commission);
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