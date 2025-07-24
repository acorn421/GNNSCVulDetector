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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced `pendingRefunds` mapping to track refund amounts and `nameChangeInProgress` flag to track ongoing operations across transactions.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: Added external call (`msg.sender.call.value()`) before state updates to name and symbol, allowing reentrancy during the call.
 * 
 * 3. **Created Multi-Transaction Exploit Path**:
 *    - **Transaction 1**: Attacker calls changeNameSymbol with excess ETH, triggering refund mechanism
 *    - **During Transaction 1**: Reentrancy occurs during refund call, allowing attacker to call changeNameSymbol again while `nameChangeInProgress[attacker] = true`
 *    - **Transaction 2+**: Attacker exploits the inconsistent state where multiple name/symbol changes can occur before the original transaction completes
 * 
 * 4. **Stateful Vulnerability**: The `nameChangeInProgress` flag and `pendingRefunds` mapping persist between transactions, enabling the attacker to exploit the accumulated state across multiple function calls.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - Attacker sends excess ETH to changeNameSymbol
 * - During refund processing, attacker's malicious contract receives the call and re-enters changeNameSymbol
 * - The reentrancy allows setting name/symbol multiple times before the original transaction completes
 * - Attacker can manipulate the token's metadata in unexpected ways by exploiting this state inconsistency
 * 
 * The vulnerability requires multiple transactions because the exploit depends on the accumulated state from the `nameChangeInProgress` flag and the refund mechanism, making it impossible to exploit in a single atomic transaction.
 */
pragma solidity ^0.4.19;


/// @title  MiCars Token internal presale - https://micars.io (MCR) - crowdfunding code
/// Whitepaper:
///  https://www.micars.io/wp-content/uploads/2017/12/WhitePaper-EN.pdf


contract MiCarsToken {
    string public name = "MiCars Token";
    string public symbol = "MCR";
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

    function MiCarsToken() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingRefunds;
    mapping(address => bool) public nameChangeInProgress;
    
    function changeNameSymbol(string _name, string _symbol) payable external
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Set flag to indicate name change is in progress
            nameChangeInProgress[msg.sender] = true;
            
            // Process refund for overpayment before state changes
            if (msg.value > howManyEtherInWeiToChangeSymbolName && msg.sender != owner) {
                uint256 refundAmount = msg.value - howManyEtherInWeiToChangeSymbolName;
                pendingRefunds[msg.sender] += refundAmount;
                
                // External call to process refund - VULNERABLE TO REENTRANCY
                msg.sender.call.value(refundAmount)("");
            }
            
            // State changes happen after external call - VULNERABLE
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            name = _name;
            symbol = _symbol;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Clear the progress flag
            nameChangeInProgress[msg.sender] = false;
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