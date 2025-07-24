/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call**: Introduced a callback to `TokenRecipient(_to).onTokenReceived(msg.sender, _value)` that executes after balance updates but before the Transfer event.
 * 
 * 2. **Contract Detection**: Added `isContract()` helper function to determine if the recipient is a smart contract, making the external call conditional and realistic.
 * 
 * 3. **Callback Interface**: The code assumes a `TokenRecipient` interface with an `onTokenReceived` function, similar to ERC777 or ERC1363 token standards.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `TokenRecipient.onTokenReceived`
 * - The malicious contract's `onTokenReceived` function doesn't immediately reenter, but instead sets up exploit state
 * - During this callback, the attacker can:
 *   - Record the current state of balances
 *   - Prepare for a future attack
 *   - Set flags or counters for later exploitation
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transfer` again, this time with a different strategy
 * - The `onTokenReceived` callback now has access to the modified state from Transaction 1
 * - The callback can now execute a more sophisticated attack, such as:
 *   - Calling `transferFrom` with pre-approved allowances
 *   - Manipulating other contract functions that depend on the balance state
 *   - Coordinating with other contracts that were notified in previous transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability exploits the fact that the external call happens after balance updates, allowing the recipient to see and react to the new state across multiple transactions.
 * 
 * 2. **Complex Attack Orchestration**: A single transaction reentrancy would be limited, but multi-transaction exploitation allows for:
 *    - Building up allowances or permissions over time
 *    - Coordinating with multiple contracts
 *    - Using information gathered in previous callbacks
 * 
 * 3. **Realistic Attack Pattern**: Real-world attacks often involve reconnaissance transactions followed by exploitation, making this pattern more realistic than simple recursive calls.
 * 
 * 4. **Stateful Callback Logic**: The malicious contract can maintain state between `onTokenReceived` calls, enabling more sophisticated attacks that build upon previous interactions.
 * 
 * The vulnerability window exists because the external call occurs after critical state changes (balance updates) but before the transaction is fully complete, and the recipient contract can leverage this timing across multiple transactions to mount a coordinated attack.
 */
pragma solidity ^0.4.18;

interface TokenRecipient {
    function onTokenReceived(address from, uint256 value) external;
}

contract EIP20Interface {    
    uint256 public totalSupply;
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract zpzToken is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
   
    string public name;                   
    uint8 public decimals;                
    string public symbol;                 

    function zpzToken(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               
        totalSupply = _initialAmount;                        
        name = _tokenName;                                   
        decimals = _decimalUnits;                            
        symbol = _tokenSymbol;                              
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Helper function to check if address is a contract
    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract if it's a smart contract
        if (isContract(_to)) {
            // External call before final state confirmation - creates reentrancy window
            TokenRecipient(_to).onTokenReceived(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
