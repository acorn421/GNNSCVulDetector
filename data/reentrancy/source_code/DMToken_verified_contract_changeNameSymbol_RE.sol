/*
 * ===== SmartInject Injection Details =====
 * Function      : changeNameSymbol
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Created `pendingNameChanges` mapping to track pending name change requests and their associated Ether values across transactions.
 * 
 * 2. **External Call Integration**: Added `nameValidator` external contract call that occurs BEFORE state updates (violating checks-effects-interactions pattern).
 * 
 * 3. **State Persistence**: The `pendingNameChanges` mapping persists between transactions, enabling multi-transaction exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 
 * **Transaction 1**: Attacker calls `changeNameSymbol` with required Ether amount:
 * - `pendingNameChanges[attacker] = msg.value` is set
 * - External call to `nameValidator.validateName()` is made
 * - Attacker's malicious validator contract can now see the pending state
 * 
 * **Transaction 2**: During the external call, attacker's validator contract calls back into `changeNameSymbol`:
 * - The original call's state (`pendingNameChanges[attacker]`) is still set
 * - Attacker can exploit the fact that the first call hasn't completed state cleanup
 * - Multiple reentrant calls can accumulate state inconsistencies
 * 
 * **Transaction 3+**: Subsequent transactions can exploit the accumulated state inconsistencies:
 * - `pendingNameChanges` mapping may contain stale values
 * - State between `name`/`symbol` and `pendingNameChanges` becomes inconsistent
 * - Attacker can chain multiple calls to manipulate the accumulated state
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires the attacker to first set up a malicious `nameValidator` contract
 * - The exploitation depends on the persistent state in `pendingNameChanges` mapping
 * - Multiple transactions are needed to: (1) Set validator, (2) Trigger initial call, (3) Exploit reentrancy during callback, (4) Potentially repeat to accumulate state issues
 * - Single transaction exploitation is prevented by the need for external contract setup and state accumulation across calls
 */
pragma solidity ^0.4.19;

/// @title  DMarket Token presale - https://dmarket.io (DMT) - crowdfunding code
/// Whitepaper:
///  https://dmarket.io/assets/documents/DMarket_white_paper_EN.pdf

// Interface for name validator contract
interface INameValidator {
    function validateName(string _name, string _symbol) external returns (bool);
}

contract DMToken {
    string public name = "DMarket Token";
    string public symbol = "DMT";
    uint8 public constant decimals = 8;  
    address public owner;

    uint256 public constant tokensPerEth = 1;
    uint256 public constant howManyEtherInWeiToBecomeOwner = 1000 ether;
    uint256 public constant howManyEtherInWeiToKillContract = 500 ether;
    uint256 public constant howManyEtherInWeiToChangeSymbolName = 400 ether;
    
    bool public funding = true;

    // The current total token supply.
    uint256 totalTokens = 1000;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Migrate(address indexed _from, address indexed _to, uint256 _value);
    event Refund(address indexed _from, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingNameChanges;
    address public nameValidator;
    
    function changeNameSymbol(string _name, string _symbol) public payable
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Store pending change amount for validation callback
            pendingNameChanges[msg.sender] = msg.value;
            
            // External call to name validator before state update
            if (nameValidator != address(0)) {
                // Vulnerable: external call before state updates
                bool isValid = INameValidator(nameValidator).validateName(_name, _symbol);
                if (!isValid) {
                    pendingNameChanges[msg.sender] = 0;
                    return;
                }
            }
            
            // State updates happen after external call (vulnerable pattern)
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            name = _name;
            symbol = _symbol;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Clear pending change only after successful update
            pendingNameChanges[msg.sender] = 0;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function setNameValidator(address _validator) public {
        if (msg.sender == owner) {
            nameValidator = _validator;
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    
    function changeOwner (address _newowner) public payable
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            owner.transfer(msg.value);
            owner.transfer(address(this).balance);
            owner=_newowner;
        }
    }

    function killContract () public payable
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToKillContract)
        {
            selfdestruct(owner);
        }
    }
    /// @notice Transfer `_value` tokens from sender's account
    /// `msg.sender` to provided account address `_to`.
    /// @notice This function is disabled during the funding.
    /// @dev Required state: Operational
    /// @param _to The address of the tokens recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
        uint256 senderBalance = balances[msg.sender];
        if (senderBalance >= _value && _value > 0) {
            senderBalance -= _value;
            balances[msg.sender] = senderBalance;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    
    function mintTo(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
    }
    

    function totalSupply() external constant returns (uint256) {
        return totalTokens;
    }

    function balanceOf(address _owner) external constant returns (uint256) {
        return balances[_owner];
    }


    function transferFrom(
         address _from,
         address _to,
         uint256 _amount
     ) public returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             return true;
         } else {
             return false;
         }
  }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         
         return true;
     }
// Crowdfunding:

    /// @notice Create tokens when funding is active.
    /// @dev Required state: Funding Active
    /// @dev State transition: -> Funding Success (only if cap reached)
    function () public payable {
        // Abort if not in Funding Active state.
        // The checks are split (instead of using or operator) because it is
        // cheaper this way.
        if (!funding) revert();
        
        // Do not allow creating 0 or more than the cap tokens.
        if (msg.value == 0) revert();
        
        uint256 numTokens = msg.value * (1000 / totalTokens);
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}