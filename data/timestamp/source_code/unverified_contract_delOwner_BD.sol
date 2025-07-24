/*
 * ===== SmartInject Injection Details =====
 * Function      : delOwner
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
 * Introduced a stateful timestamp dependence vulnerability by implementing a cooldown mechanism that uses block.timestamp for time-based access control. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Persistence**: Added state variables (lastDeletionTime, emergencyDeletionTime) that persist between transactions and control access to the function
 * 2. **Multi-Transaction Exploitation**: The vulnerability can be exploited through:
 *    - Miners manipulating block timestamps across multiple blocks to bypass cooldown periods
 *    - Sequential transactions where timing manipulation accumulates advantages
 *    - Emergency state exploitation requiring multiple deletion operations to reach critical thresholds
 * 
 * 3. **Specific Vulnerability Patterns**:
 *    - Uses block.timestamp for critical access control without proper validation
 *    - Stores timing information in state variables for later use in security checks
 *    - Creates timing-dependent logic that miners can manipulate across multiple transactions
 * 
 * 4. **Multi-Transaction Attack Scenario**:
 *    - Transaction 1: Perform first deletion, sets lastDeletionTime
 *    - Transaction 2: Miner manipulates timestamp to bypass cooldown and perform rapid successive deletions
 *    - Transaction 3+: Continue exploiting timestamp manipulation to remove all owners or reach emergency conditions
 * 
 * The vulnerability is realistic as cooldown periods are common security practices, but becomes exploitable when relying on manipulable block.timestamp values across multiple transactions.
 */
pragma solidity ^0.4.24;

contract Owned {
    
    /// 'owner' is the only address that can call a function with 
    /// this modifier
    address public initOwner;
    address[] public owner;
    address internal newOwner;
    
    // === Injected variables for timestamp dependence vulnerability ===
    uint256 public lastDeletionTime;
    uint256 public emergencyDeletionTime;
    
    ///@notice The constructor assigns the message sender to be 'owner'
    constructor() public {
        initOwner = msg.sender;
        owner.push(msg.sender);
        // Initialize injected variables
        lastDeletionTime = 0;
        emergencyDeletionTime = 0;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Implement cooldown period based on block.timestamp
        uint256 cooldownPeriod = 3600; // 1 hour cooldown
        
        // Check if enough time has passed since last deletion
        require(block.timestamp >= lastDeletionTime + cooldownPeriod, "Cooldown period not met");
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint i=0;i<owner.length;i++) {
            if (owner[i] == _addedOwner) {
                owner[i] = owner[owner.length - 1];
                owner.length -= 1;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Store current block timestamp for future cooldown checks
                lastDeletionTime = block.timestamp;
                
                // If deletion reduces owners to critical threshold, extend cooldown
                if (owner.length <= 2) {
                    emergencyDeletionTime = block.timestamp;
                }
                
                break;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
