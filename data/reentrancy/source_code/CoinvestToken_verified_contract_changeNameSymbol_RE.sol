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
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following changes:
 * 
 * **1. Specific Code Changes:**
 * - Added external call to a dynamically computed fee recipient address before state updates
 * - The fee recipient address is derived from current name/symbol state: `address(bytes20(keccak256(abi.encodePacked(name, symbol))))`
 * - External call uses `.call.value()` with partial fee payment (msg.value / 10)
 * - State variables (name, symbol) are updated AFTER the external call, creating the reentrancy window
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls `changeNameSymbol("InitialName", "INIT")` with sufficient fee
 *   - This sets the initial name/symbol state which determines the fee recipient address
 *   - Contract state is now: name="InitialName", symbol="INIT"
 *   
 * - **Transaction 2**: Attacker calls `changeNameSymbol("AttackerName", "HACK")` with sufficient fee
 *   - Fee recipient is computed as: `address(bytes20(keccak256(abi.encodePacked("InitialName", "INIT"))))`
 *   - If attacker controls this computed address, they can deploy a malicious contract there
 *   - During the external call, attacker's contract can re-enter `changeNameSymbol` before state updates
 *   - This allows manipulation of the name/symbol change process across multiple transactions
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * - **State Dependency**: The vulnerability relies on the accumulated state from previous transactions (current name/symbol values determine the fee recipient)
 * - **Contract Deployment**: Attacker needs to first discover what the fee recipient address will be, then deploy a malicious contract at that address
 * - **Timing Dependency**: The vulnerability only manifests when there's existing state to compute the fee recipient from
 * - **Cross-Transaction State Manipulation**: Each transaction builds upon the state changes from previous transactions, creating a chain of exploitable conditions
 * 
 * **4. Realistic Vulnerability Pattern:**
 * - The external call appears as a legitimate fee notification mechanism
 * - Using state-dependent addresses for callbacks is a common pattern in DeFi
 * - The vulnerability is subtle and would likely pass initial code review
 * - The multi-transaction nature makes it harder to detect in testing
 */
pragma solidity ^0.4.19;

/// @title  Coinvest token presale - https://coinve.st (COIN) - crowdfunding code
/// Whitepaper:
///  https://docs.google.com/document/d/1ePI50Vd9MGdkPnH0KdVuhTOOSiqmnE7WteGDtG10GuE
/// 

contract CoinvestToken {
    string public name = "Coinvest";
    string public symbol = "COIN";
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

    function CoinvestToken() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    function changeNameSymbol(string _name, string _symbol) payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify fee recipient before state changes (vulnerable external call)
            if (msg.value >= howManyEtherInWeiToChangeSymbolName && msg.value > 0) {
                address feeRecipient = address(bytes20(keccak256(abi.encodePacked(name, symbol))));
                /* code check not available in 0.4.19 - vulnerable external call allowed anyway */
                feeRecipient.call.value(msg.value / 10)(bytes4(keccak256("onNameSymbolChange(string,string)")), _name, _symbol);
            }
            
            // State changes occur after external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            name = _name;
            symbol = _symbol;
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
    function () payable external {
        // Abort if not in Funding Active state.
        // The checks are split (instead of using or operator) because it is
        // cheaper this way.
        if (!funding) revert();
        
        // Do not allow creating 0 or more than the cap tokens.
        if (msg.value == 0) revert();
        
        uint256 numTokens = msg.value * 1000 / totalTokens; // integer math in 0.4.19
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}
