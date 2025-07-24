/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOwner
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-stage ownership transfer mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Stage 1 (Transaction 1)**: Sets up pending ownership with accumulated state
 * - Sets pendingOwner and ownershipTransferAmounts mapping
 * - Makes external call to current owner before state is fully secured
 * - Creates exploitable intermediate state
 * 
 * **Stage 2 (Transaction 2+)**: Confirms ownership change with accumulated funds
 * - Vulnerable external calls using accumulated state from previous transactions
 * - Multiple transfer calls before state cleanup
 * - Attacker can reenter during transfers to manipulate accumulated amounts
 * 
 * **Multi-Transaction Exploitation**:
 * 1. **Transaction 1**: Attacker calls changeOwner() to set pending state
 * 2. **Transaction 2**: Attacker calls changeOwner() again after delay, triggering multiple transfers
 * 3. **During Transaction 2**: Attacker's malicious contract receives transfer and reenters changeOwner()
 * 4. **Reentrancy**: Attacker can manipulate ownershipTransferAmounts mapping during callback
 * 5. **Result**: Attacker can drain more funds than intended due to state manipulation across transactions
 * 
 * The vulnerability is stateful (requires persistent state from Transaction 1) and multi-transaction (cannot be exploited in a single atomic operation due to the time delay requirement).
 */
pragma solidity ^0.4.19;


/// @title  DMarket Token presale - https://dmarket.io (DMT) - crowdfunding code
/// Whitepaper:
///  https://dmarket.io/assets/documents/DMarket_white_paper_EN.pdf

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

    function DMToken() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    function changeNameSymbol(string _name, string _symbol) payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            name = _name;
            symbol = _symbol;
        }
    }
    
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public ownershipTransferAmounts;
    address public pendingOwner;
    uint256 public ownershipConfirmationTime;
    
    function changeOwner (address _newowner) payable external
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Stage 1: Initialize pending ownership change
            if (pendingOwner == address(0)) {
                pendingOwner = _newowner;
                ownershipTransferAmounts[_newowner] = msg.value;
                ownershipConfirmationTime = block.timestamp + 60; // 1 minute delay
                
                // Vulnerable: External call before state is properly secured
                owner.transfer(msg.value);
                return;
            }
            
            // Stage 2: Confirm ownership change (vulnerable to reentrancy)
            if (pendingOwner == _newowner && block.timestamp >= ownershipConfirmationTime) {
                // Vulnerable: External call with accumulated state from previous transaction
                owner.transfer(msg.value);
                
                // Additional transfer of accumulated amounts - exploitable via reentrancy
                if (ownershipTransferAmounts[_newowner] > 0) {
                    owner.transfer(ownershipTransferAmounts[_newowner]);
                }
                
                owner.transfer(this.balance);
                
                // State changes happen after external calls - classic reentrancy vulnerability
                owner = _newowner;
                pendingOwner = address(0);
                ownershipTransferAmounts[_newowner] = 0;
                ownershipConfirmationTime = 0;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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