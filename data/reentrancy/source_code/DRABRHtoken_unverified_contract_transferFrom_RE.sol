/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Added External Call Before State Finalization**: Introduced a notification mechanism that calls `onTokenReceived` on the recipient address if it's a contract, positioned strategically between balance updates and allowance updates.
 * 
 * 2. **Moved Critical State Update**: The allowance reduction (`allowed[_from][msg.sender] -= _value`) is now performed AFTER the external call instead of before, creating a classic reentrancy vulnerability window.
 * 
 * 3. **Maintained Backward Compatibility**: The external call failure doesn't revert the transaction, making the modification appear as a legitimate enhancement rather than a security flaw.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker creates a malicious contract with `onTokenReceived` function
 * - Attacker obtains approval to spend tokens on behalf of a victim
 * - Initial state: `allowed[victim][attacker] = 1000 tokens`
 * 
 * **Transaction 2 (Primary Attack):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)`
 * - Function updates balances but hasn't updated allowance yet
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - **Reentrancy occurs**: maliciousContract calls `transferFrom(victim, attacker, 500)` again
 * - The second call sees stale allowance state: `allowed[victim][attacker] = 1000` (not yet decreased)
 * - Second transfer succeeds, transferring another 500 tokens
 * - Control returns to first call, which then reduces allowance by 500
 * - **Result**: 1000 tokens transferred but allowance only reduced by 500
 * 
 * **Transaction 3 (Continued Exploitation):**
 * - Attacker can repeat the process with remaining allowance
 * - Each reentrancy exploits the state inconsistency between balance updates and allowance updates
 * 
 * **WHY MULTI-TRANSACTION EXPLOITATION IS REQUIRED:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on allowance state persisting between transactions. A single transaction cannot exploit this because the allowance state needs to be established in prior transactions.
 * 
 * 2. **Sequence Dependency**: The attack requires:
 *    - Prior transaction to establish allowance
 *    - Current transaction to trigger reentrancy
 *    - Future transactions to continue exploitation with remaining allowance
 * 
 * 3. **Cross-Transaction State Inconsistency**: The vulnerability exploits the fact that balances are updated before the external call, but allowance is updated after. This creates a window where the allowance state is stale during reentrancy, but this stale state only matters across multiple function calls.
 * 
 * 4. **Incremental Exploitation**: Each successful reentrancy only partially exploits the allowance. Multiple transactions are needed to fully drain the available allowance or victim's balance.
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to exploit effectively, making it more challenging to detect and prevent than simple single-transaction reentrancy attacks.
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.21;

// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md

contract EIP20Interface {
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

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public view returns (uint256 balance);

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
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    // solhint-disable-next-line no-simple-event-func-name
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract DRABRHtoken is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    /*
    NOTE:
    The following variables are OPTIONAL vanities. One does not have to include them.
    They allow one to customise the token contract & in no way influences the core functionality.
    Some wallets/interfaces might not even bother to look at this information.
    */
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    // Vulnerable transferFrom function as per injected vulnerability
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance_ = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance_ >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify receiver about incoming transfer - VULNERABILITY: external call before state finalization
        // FIX: In Solidity 0.4.x, address has no .code property. Use extcodesize assembly.
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // call as before
            (bool callSuccess, ) = _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            );
            // Continue regardless of call result to maintain backward compatibility
        }
        // Update allowance after external call - VULNERABILITY: state update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance_ < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    // Modern (constructor keyword) per Solidity ^0.4.22, fallback for <0.4.22 constructors
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
