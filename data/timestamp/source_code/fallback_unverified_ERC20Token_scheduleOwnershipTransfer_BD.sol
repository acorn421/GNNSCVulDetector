/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleOwnershipTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction ownership transfer system. The vulnerability requires: 1) First transaction: scheduleOwnershipTransfer() to set up the transfer with a future timestamp, 2) Second transaction: executeScheduledTransfer() to execute the transfer when the timestamp condition is met. The vulnerability lies in the executeScheduledTransfer() function which relies on 'now' (block.timestamp) for time validation. Miners can manipulate timestamps within ~900 seconds, allowing them to potentially execute transfers earlier than intended or prevent execution by setting timestamps backwards within the allowed range. The state persists between transactions through the scheduledTransfer struct, making this a stateful, multi-transaction vulnerability.
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

    /// @dev Struct to store scheduled transfer information
    struct ScheduledTransfer {
        address newOwner;
        uint256 activationTime;
        bool isActive;
    }
    
    /// @dev Storage for scheduled ownership transfer
    ScheduledTransfer public scheduledTransfer;
    
    /// @dev change token holder
    function changeTokenHolder(address _tokenHolder) public onlyInitOwner {
        allocTokenHolder = _tokenHolder;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    /// @dev Schedule a delayed ownership transfer with time-based activation
    /// @param _newOwner The address to transfer ownership to
    /// @param _activationTime The timestamp when the transfer becomes active
    function scheduleOwnershipTransfer(address _newOwner, uint256 _activationTime) public onlyInitOwner {
        require(_newOwner != address(0));
        require(_activationTime > now);
    
        scheduledTransfer.newOwner = _newOwner;
        scheduledTransfer.activationTime = _activationTime;
        scheduledTransfer.isActive = true;
    }
    
    /// @dev Execute a previously scheduled ownership transfer
    function executeScheduledTransfer() public {
        require(scheduledTransfer.isActive);
        require(now >= scheduledTransfer.activationTime);
    
        // Vulnerable: Only checks if current time is >= activation time
        // Miners can manipulate timestamp within ~900 seconds
        initOwner = scheduledTransfer.newOwner;
    
        // Clear the scheduled transfer
        scheduledTransfer.isActive = false;
        scheduledTransfer.newOwner = address(0);
        scheduledTransfer.activationTime = 0;
    }
    
    /// @dev Cancel a scheduled ownership transfer
    function cancelScheduledTransfer() public onlyInitOwner {
        require(scheduledTransfer.isActive);
    
        scheduledTransfer.isActive = false;
        scheduledTransfer.newOwner = address(0);
        scheduledTransfer.activationTime = 0;
    }
    
    /// @dev Check if there's an active scheduled transfer
    function getScheduledTransfer() public view returns (address newOwner, uint256 activationTime, bool isActive) {
        return (scheduledTransfer.newOwner, scheduledTransfer.activationTime, scheduledTransfer.isActive);
    }
    // === END FALLBACK INJECTION ===

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
