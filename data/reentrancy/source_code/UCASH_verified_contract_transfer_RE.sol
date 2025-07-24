/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a call to `_to.call()` with `onTokenReceived()` signature before balance modifications
 * 2. **Violated Checks-Effects-Interactions Pattern**: Moved state updates (`balances[msg.sender] -= _value` and `balances[_to] += _value`) to occur AFTER the external call
 * 3. **Created Callback Mechanism**: The external call allows recipient contracts to execute arbitrary logic during the transfer process
 * 4. **Maintained Function Signature**: Preserved all original parameters, return types, and core functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract `MaliciousReceiver` with `onTokenReceived()` function
 * - Attacker obtains some initial tokens through legitimate means
 * - Initial state: Attacker has 100 tokens, contract has 1000 tokens
 * 
 * **Transaction 2 (First Attack):**
 * - Attacker calls `transfer(maliciousReceiver, 100)` 
 * - Flow: `require(balances[attacker] >= 100)` ✓ (passes)
 * - External call triggers: `maliciousReceiver.onTokenReceived(attacker, 100)`
 * - **Inside onTokenReceived**: Malicious contract calls `transfer(attacker, 100)` again
 * - **Reentrancy occurs**: Second transfer executes before first transfer's state updates
 * - Second transfer's require check: `balances[attacker] >= 100` ✓ (still passes - balances not updated yet)
 * - Second transfer completes its external call and state updates first
 * - First transfer then completes its state updates
 * - **Result**: Attacker effectively transferred 100 tokens but received 200 tokens worth of state changes
 * 
 * **Transaction 3+ (Repeated Exploitation):**
 * - Attacker can repeat the process, each time leveraging the accumulated unauthorized tokens
 * - Each transaction builds upon the state corruption from previous transactions
 * - The vulnerability compounds across multiple transactions
 * 
 * **Why Multi-Transaction Requirement:**
 * 1. **State Accumulation**: Each exploit round increases the attacker's unauthorized balance, enabling larger subsequent exploits
 * 2. **Persistent State Corruption**: Balance inconsistencies from one transaction persist and enable future exploitations
 * 3. **Coordination Requirement**: Attacker needs to deploy malicious contract (Transaction 1) and then execute coordinated attack transactions
 * 4. **Escalating Impact**: Later transactions can exploit larger amounts due to previously accumulated unauthorized balances
 * 
 * **Technical Details:**
 * - The vulnerability is NOT exploitable in a single transaction because it requires the external contract to be deployed first
 * - The state corruption persists between transactions in the `balances` mapping
 * - Each successful reentrancy increases the attacker's balance, enabling progressively larger exploits
 * - The attack pattern requires multiple coordinated calls to achieve significant financial impact
 * 
 * This creates a realistic, stateful reentrancy vulnerability that demonstrates how state corruption can compound across multiple transactions, making it particularly dangerous for token contracts.
 */
/*
This is the UCASH Ethereum smart contract

UCASH Implements the EIP20 token standard: https://github.com/ethereum/EIPs/issues/20

The smart contract code can be viewed here: https://github.com/UdotCASH/UCASH-ERC20.git

For more info about UCASH and the U.CASH ecosystem, visit https://u.cash
.*/

pragma solidity ^0.4.8;

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

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract UCASH is EIP20Interface {
    uint256 constant MAX_UINT256 = 2**256 - 1;

    string public name;
    uint8 public decimals;
    string public symbol;

    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    function UCASH() public {
        totalSupply = 21*10**9*10**8;               //UCASH totalSupply
        balances[msg.sender] = totalSupply;         //Allocate UCASH to contract deployer
        name = "UCASH";
        decimals = 8;                               //Amount of decimals for display purposes
        symbol = "UCASH";
    }

    // This is the vulnerable function! Do NOT fix the vulnerability.
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract if it exists (vulnerable external call)
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            // Call to external contract before state updates (VULNERABILITY)
            if(!_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
                revert();
            }
        }
        // State updates happen AFTER external call (VULNERABILITY)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
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

    function allowance(address _owner, address _spender)
    public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
