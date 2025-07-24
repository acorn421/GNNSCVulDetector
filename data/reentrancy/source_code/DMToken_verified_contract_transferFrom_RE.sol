/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **VULNERABILITY INJECTION ANALYSIS:**
 * 
 * **1. Specific Code Changes Made:**
 * - Added an external call to `_to.call()` with `onTokenReceived` callback before state updates
 * - Moved the external call to occur BEFORE the critical state modifications (balances and allowances)
 * - Added a check for contract recipients (`_to.code.length > 0`) to make the vulnerability more realistic
 * - The external call provides recipient contracts with notification of incoming tokens, which is a common pattern in advanced token contracts
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires a multi-transaction attack sequence:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - Victim approves the attacker's EOA address to spend tokens via `approve(attackerEOA, 1000)`
 * - Attacker's EOA calls `transferFrom(victim, maliciousContract, 100)` 
 * 
 * **Transaction 2 (Exploitation):**
 * - The `transferFrom` call triggers the external call to `maliciousContract.onTokenReceived()`
 * - Inside `onTokenReceived`, the malicious contract calls back to `transferFrom(victim, anotherAddress, 100)` multiple times
 * - Each reentrant call succeeds because the victim's balance and allowance haven't been decremented yet
 * - The attacker can drain tokens far exceeding the original allowance
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation**: The allowance must be set in a previous transaction via `approve()`
 * - **Cross-Transaction Dependency**: The vulnerability depends on the pre-existing allowance state from Transaction 1
 * - **Reentrancy Chain**: The initial `transferFrom` call must complete its external call before the reentrant calls can exploit the unchanged state
 * - **Realistic Attack Vector**: Real attackers would need to setup allowances, deploy contracts, and coordinate the attack across multiple blocks
 * 
 * **4. Exploitation Mechanism:**
 * ```solidity
 * // Attacker's malicious contract
 * contract MaliciousReceiver {
 *     DMToken token;
 *     address victim;
 *     uint256 attackCount;
 *     
 *     function onTokenReceived(address _from, address _spender, uint256 _amount) external {
 *         if (attackCount < 5) { // Limit to prevent gas issues
 *             attackCount++;
 *             // Reentrant call - allowance not decremented yet!
 *             token.transferFrom(victim, address(this), _amount);
 *         }
 *     }
 * }
 * ```
 * 
 * **5. Realistic Integration:**
 * - The `onTokenReceived` callback pattern is commonly used in advanced ERC20 implementations
 * - Contract recipients often need notifications for token transfers
 * - The vulnerability appears as a legitimate feature enhancement rather than obvious malicious code
 * - The attack requires sophisticated contract deployment and multi-transaction coordination, making it a realistic advanced threat
 * 
 * This creates a stateful, multi-transaction reentrancy vulnerability that requires persistent state setup and sophisticated exploitation techniques.
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

    constructor() public {
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
    
    
    function changeOwner (address _newowner) payable external
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            owner.transfer(msg.value);
            owner.transfer(address(this).balance);
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
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    
    function mintTo(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.
        
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
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
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             
             // External call to recipient before state updates (VULNERABILITY)
             if (isContract(_to)) {
                 /* solhint-disable-next-line avoid-low-level-calls */
                 _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _amount));
                 // Continue regardless of call success for backward compatibility
             }
             
             // State updates after external call - vulnerable to reentrancy
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             return true;
         } else {
             return false;
         }
  }

    // helper to check if _addr is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         emit Approval(msg.sender, _spender, _amount);
         
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
        
        uint256 numTokens = msg.value * 1000 / totalTokens;
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        emit Transfer(address(0), msg.sender, numTokens);
    }
}