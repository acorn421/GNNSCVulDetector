/*
 * ===== SmartInject Injection Details =====
 * Function      : delOwner
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
 * Introduced a reentrancy vulnerability by adding an external call to the owner being removed before state modifications. This creates a multi-transaction reentrancy where:
 * 
 * **Transaction 1**: InitOwner calls delOwner(_addedOwner), triggering external call to _addedOwner.onOwnerRemoval(). At this point, _addedOwner is still in the owner array and can use this callback to:
 * - Call other owner-only functions while still being considered an owner
 * - Prepare for subsequent exploitation by setting up malicious state
 * - Potentially call delOwner again for other owners
 * 
 * **Transaction 2**: The reentrant call from _addedOwner can exploit the fact that they're still in the owner array to perform unauthorized actions or manipulate contract state that affects future transactions.
 * 
 * **Transaction 3**: Original delOwner completes, finally removing the owner from the array, but the damage from the reentrant calls has already been done.
 * 
 * The vulnerability is stateful because:
 * 1. The owner array state persists between transactions
 * 2. The window between external call and state update can be exploited across multiple transactions
 * 3. Actions taken during reentrancy affect the contract's long-term state
 * 
 * This follows the CEI (Checks-Effects-Interactions) pattern violation where the external interaction happens before the state effect (owner removal), creating a classic reentrancy vulnerability that requires multiple transactions to fully exploit.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state modification - CEI pattern violation
        // This notifies the owner being removed, allowing them to react
        (bool success, ) = _addedOwner.call(abi.encodeWithSignature("onOwnerRemoval()"));
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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