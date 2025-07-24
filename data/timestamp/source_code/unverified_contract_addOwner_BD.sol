/*
 * ===== SmartInject Injection Details =====
 * Function      : addOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp-dependent access control mechanism that creates a multi-transaction exploitation scenario. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added `ownerAdditionTime` mapping to store when each owner was added
 * 2. Added `lastOwnerAddTime` state variable to track the last owner addition time
 * 3. Implemented a "safe window" check using `block.timestamp % 300 < 60` that only allows owner additions during specific time periods (first 60 seconds of every 5-minute window)
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker monitors the blockchain and waits for the "safe window" (when `block.timestamp % 300 < 60`)
 * 2. **Transaction 2**: During the safe window, attacker calls `addOwner()` with a malicious address
 * 3. **Transaction 3+**: The newly added malicious owner can now perform privileged operations in subsequent transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single transaction because the attacker must wait for the correct timestamp window
 * - The state changes (`ownerAdditionTime` and `lastOwnerAddTime`) persist between transactions and create the conditions for exploitation
 * - The attacker needs to monitor blockchain state across multiple blocks to time their attack correctly
 * - Once a malicious owner is added, they need separate transactions to abuse their privileges
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world contracts that implement time-based access controls for administrative functions, where developers mistakenly rely on predictable timestamp patterns that can be exploited by patient attackers who monitor blockchain timing.
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public ownerAdditionTime;
    uint256 public lastOwnerAddTime;
    
    function addOwner(address _newOwner) public onlyInitOwner ownerNotAdded(_newOwner) returns(bool) {
        // Time-based access control: Only allow adding owners during "safe windows"
        // Safe window is defined as blocks where timestamp is divisible by 300 (5 minutes)
        require(block.timestamp % 300 < 60, "Owner addition only allowed during safe time windows");
        
        // Store the timestamp when this owner was added
        ownerAdditionTime[_newOwner] = block.timestamp;
        lastOwnerAddTime = block.timestamp;
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    
    /// @dev change token holder
    function changeTokenHolder(address _tokenHolder) public onlyInitOwner {
        allocTokenHolder = _tokenHolder;
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