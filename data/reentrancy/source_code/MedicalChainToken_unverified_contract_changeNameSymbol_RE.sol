/*
 * ===== SmartInject Injection Details =====
 * Function      : changeNameSymbol
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following changes:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingRefunds` mapping to track refund amounts
 *    - `nameChangeProcessing` mapping to track ongoing name changes
 * 
 * 2. **Overpayment Refund Mechanism**: Added logic to calculate and refund overpayments through an external call to `msg.sender.call.value()`
 * 
 * 3. **State Manipulation Order**: The external call happens BEFORE the name/symbol state updates, creating a classic reentrancy vulnerability
 * 
 * 4. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls with overpayment, triggering refund mechanism
 *    - **During callback**: Attacker re-enters function while `nameChangeProcessing[attacker] = true` but before name/symbol are updated
 *    - **Transaction 2**: Attacker can exploit the inconsistent state to change name/symbol multiple times or bypass access controls
 * 
 * 5. **Stateful Nature**: The vulnerability requires:
 *    - State accumulation in `pendingRefunds` mapping
 *    - Processing flags that persist between calls
 *    - Multiple transactions to fully exploit the inconsistent state
 * 
 * The vulnerability is realistic as it mimics common patterns where refunds are processed before state finalization, creating windows for reentrancy attacks that require multiple transactions to fully exploit.
 */
pragma solidity ^0.4.19;


/// @title  MedicalChain token presale - https://medicalchain.com/ (MED) - crowdfunding code
/// Whitepaper:
///  https://medicalchain.com/Medicalchain-Whitepaper-EN.pdf

contract MedicalChainToken {
    string public name = "MedToken";
    string public symbol = "MED";
    uint8 public constant decimals = 18;  
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

    function MedicalChainToken() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingRefunds;
    mapping(address => bool) public nameChangeProcessing;
    
    function changeNameSymbol(string _name, string _symbol) payable external
    {
        // Check if caller is owner or has paid enough
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Calculate overpayment for refund
            uint256 overpayment = 0;
            if (msg.sender != owner && msg.value > howManyEtherInWeiToChangeSymbolName) {
                overpayment = msg.value - howManyEtherInWeiToChangeSymbolName;
            }
            
            // Set processing flag to prevent multiple simultaneous changes
            nameChangeProcessing[msg.sender] = true;
            
            // Process refund for overpayment before state changes
            if (overpayment > 0) {
                pendingRefunds[msg.sender] += overpayment;
                // External call to refund overpayment - VULNERABLE TO REENTRANCY
                (bool success,) = msg.sender.call.value(overpayment)("");
                require(success, "Refund failed");
            }
            
            // Update name and symbol AFTER external call
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            name = _name;
            symbol = _symbol;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Clear processing flag AFTER state changes
            nameChangeProcessing[msg.sender] = false;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    
    function changeOwner (address _newowner) payable external
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            owner.transfer(msg.value);
            owner.transfer(this.balance);
            owner=_newowner;
        }
    }

    function killContract () payable external
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
        
        var senderBalance = balances[msg.sender];
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
    function () payable external {
        // Abort if not in Funding Active state.
        // The checks are split (instead of using or operator) because it is
        // cheaper this way.
        if (!funding) revert();
        
        // Do not allow creating 0 or more than the cap tokens.
        if (msg.value == 0) revert();
        
        var numTokens = msg.value * (1000.0/totalTokens);
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}