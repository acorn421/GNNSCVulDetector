/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTokenDistribution
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
 * This vulnerability introduces a multi-transaction timestamp dependence issue where token distributions can be scheduled and executed based on block timestamps. The vulnerability requires multiple transactions to exploit: (1) First, an attacker schedules a distribution with a specific delay, (2) The scheduled distribution state persists in the contract, (3) A malicious miner can manipulate the block timestamp to execute the distribution earlier than intended. This creates a stateful vulnerability where the exploit depends on the persistent scheduled distribution state and requires coordination between multiple transactions and potentially compromised miners.
 */
pragma solidity ^0.4.24;

contract Owned {
    
    /// 'owner' is the only address that can call a function with 
    /// this modifier
    address public initOwner;
    address[] public owner;
    address internal newOwner;
    
    ///@notice The constructor assigns the message sender to be 'owner'
    constructor() public {
        initOwner = msg.sender;
        owner.push(msg.sender);
    }
    
    modifier onlyInitOwner() {
        require (msg.sender == initOwner);
        _;
    }
    
    modifier onlyOwners(address _owner) {
        bool _isOwner;
        for (uint i=0; i<owner.length; i++) {
            if (owner[i] == _owner) {
                _isOwner = true;
                break;
            }
        }
        require (_isOwner == true);
        _;
    }
    
    modifier ownerNotAdded(address _newOwner) {
        bool _added = false;
        for (uint i=0;i<owner.length;i++) {
            if (owner[i] == _newOwner) {
                _added = true;
                break;
            }
        }
        require (_added == false);
        _;
    }
    
    modifier ownerAdded(address _newOwner) {
        bool _added = false;
        for (uint i=0;i<owner.length;i++) {
            if (owner[i] == _newOwner) _added = true;
        }
        require (_added == true);
        _;
    }
    
    ///change the owner
    function addOwner(address _newOwner) public onlyInitOwner ownerNotAdded(_newOwner) returns(bool) {
        owner.push(_newOwner);
        return true;
    }
    
    function delOwner(address _addedOwner) public onlyInitOwner ownerAdded(_addedOwner) returns(bool) {
        for (uint i=0;i<owner.length;i++) {
            if (owner[i] == _addedOwner) {
                owner[i] = owner[owner.length - 1];
                owner.length -= 1;
            }
        }
        return true;
    }
    
    function changeInitOwner(address _newOwner) public onlyInitOwner {
        initOwner = _newOwner;
    }
}

library SafeMath {

  /**
   * @dev Multiplies two numbers, throws on overflow.
   */
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    if (a == 0) {
      return 0;
    }
    c = a * b;
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
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20Token {
    /* This is a slight change to the ERC20 base standard.
    function totalSupply() constant returns (uint256 supply);
    is replaced with:
    uint256 public totalSupply;
    This automatically creates a getter function for the totalSupply.
    This is moved to the base contract since public getter functions are not
    currently recognised as an implementation of the matching abstract
    function by the compiler.
    */
    /// total amount of tokens
    uint256 public totalSupply;
    
    /// user tokens
    mapping (address => uint256) public balances;
    
    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) constant public returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success);
    
    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) public returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract TxProxy is Owned {
    
    uint256 decimals = 18;
    
    address public USEAddr = 0xd9485499499d66B175Cf5ED54c0a19f1a6Bcb61A;
    
    /// @dev token holder
    address public allocTokenHolder;
    
    /// @dev Scheduled token distribution state
    struct ScheduledDistribution {
        address[] recipients;
        uint256[] amounts;
        uint256 scheduledTime;
        bool executed;
        address scheduler;
    }
    
    mapping(uint256 => ScheduledDistribution) public scheduledDistributions;
    uint256 public distributionCounter;
    uint256 public constant DISTRIBUTION_DELAY = 1 hours;
    
    /// @dev change token holder
    function changeTokenHolder(address _tokenHolder) public onlyInitOwner {
        allocTokenHolder = _tokenHolder;
    }
    
    /// @dev Schedule a token distribution to be executed after a delay
    /// @param _recipients Array of recipient addresses
    /// @param _amounts Array of token amounts to distribute
    /// @param _delayHours Hours to delay the distribution
    function scheduleTokenDistribution(address[] _recipients, uint256[] _amounts, uint256 _delayHours) public onlyOwners(msg.sender) {
        require(_recipients.length == _amounts.length);
        require(_recipients.length > 0);
        require(_delayHours >= 1);
        
        uint256 distributionId = distributionCounter++;
        uint256 executionTime = now + (_delayHours * 1 hours);
        
        scheduledDistributions[distributionId] = ScheduledDistribution({
            recipients: _recipients,
            amounts: _amounts,
            scheduledTime: executionTime,
            executed: false,
            scheduler: msg.sender
        });
    }
    
    /// @dev Execute a scheduled token distribution
    /// @param _distributionId ID of the distribution to execute
    function executeScheduledDistribution(uint256 _distributionId) public {
        ScheduledDistribution storage dist = scheduledDistributions[_distributionId];
        
        require(dist.recipients.length > 0);
        require(!dist.executed);
        require(now >= dist.scheduledTime);
        
        // Vulnerable: Using block.timestamp for critical timing logic
        // Miners can manipulate timestamp within ~900 seconds
        // This creates a multi-transaction vulnerability where:
        // 1. Attacker schedules distribution with minimal delay
        // 2. Miner manipulates timestamp to execute earlier than intended
        // 3. State persists between transactions allowing exploitation
        
        dist.executed = true;
        
        for(uint i = 0; i < dist.recipients.length; i++){
            uint256 value = dist.amounts[i] * 10 ** decimals;
            require(ERC20Token(USEAddr).transferFrom(allocTokenHolder, dist.recipients[i], value) == true);
        }
    }
    
    /// @dev This owner allocate token for candy airdrop
    /// @param _owners The address of the account that owns the token
    /// @param _values The amount of tokens
	function allocateToken(address[] _owners, uint256[] _values) public onlyOwners(msg.sender) {
	   require (_owners.length == _values.length);
       for(uint i = 0; i < _owners.length ; i++){
           uint256 value = _values[i] * 10 ** decimals;
           require(ERC20Token(USEAddr).transferFrom(allocTokenHolder, _owners[i], value) == true);
        }
    }
}
