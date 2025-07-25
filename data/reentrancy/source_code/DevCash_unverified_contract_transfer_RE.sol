/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call to recipient if it's a contract address (checking code.length > 0)
 * 2. The external call invokes `onTokenReceived(address,uint256)` callback on the recipient
 * 3. State updates (balance modifications) occur AFTER the external call, violating Checks-Effects-Interactions pattern
 * 4. Used low-level assembly call to avoid reverting on failed external calls
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with onTokenReceived callback
 * 2. **Transaction 2**: Victim calls transfer() to send tokens to attacker's contract
 * 3. **During callback**: Malicious contract re-enters transfer() before balances are updated
 * 4. **Transaction 3+**: Subsequent transfers operate on corrupted state from previous reentrancy
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability leverages persistent state (balances mapping) that survives between transactions
 * - Multiple users can interact with the same corrupted state across different transactions
 * - The attack requires setting up the malicious contract in one transaction, then exploiting it in subsequent transactions
 * - The effects accumulate across transactions, allowing repeated exploitation of the same vulnerability
 * 
 * **Stateful Nature:**
 * - Balance inconsistencies persist in contract storage between transactions
 * - Multiple attackers can exploit the same vulnerability simultaneously across different transactions
 * - The corrupted state affects all future interactions with the contract until corrected
 * 
 * This creates a realistic vulnerability where the reentrancy window allows multiple withdrawals before balance deduction, with effects persisting across transaction boundaries.
 */
/*
This is the DevCash Token Contract

DevCash Implements the EIP20 token standard: https://github.com/ethereum/EIPs/issues/20

DevCash will be distributed through bounties at "Blockchain Developers United" and affiliated meetups

Devcash is intended to incentivize proper Blockchain developer training, grant access to developer resources, and act a medium of exchange in the developer marketplace

DevCash is cash for the developer economy

The smart contract code can be viewed here: https://github.com/BlockchainDevelopersUnited/DevCash-ERC20

For more info about DevCash, visit https://u.cash
.*/

pragma solidity ^0.4.8;

contract EIP20Interface {
    mapping(address => uint256) internal balances; // ADDED to fix undeclared identifier error
    
    /// total amount of tokens
    uint256 public totalSupply;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public view returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call before state update - creates reentrancy window
        if (isContract(_to)) {
            // Call onTokenReceived callback if recipient is a contract
            bool callResult;
            bytes memory callData = abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value);
            assembly {
                callResult := call(gas(), _to, 0, add(callData, 0x20), mload(callData), 0, 0)
            }
        }
        
        // State updates occur AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Helper function for isContract check
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

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


contract DevCash is EIP20Interface {

    uint256 constant MAX_UINT256 = 2**256 - 1;

    mapping (address => mapping (address => uint256)) allowed; // moved here so both contracts have access

    string public name;
    uint8 public decimals;
    string public symbol;

     constructor() public {
        totalSupply = 21*10**8*10**8;               //DevCash totalSupply
        balances[msg.sender] = totalSupply;         //Allocate DevCash to contract deployer
        name = "DevCash";
        decimals = 8;                               //Amount of decimals for display purposes
        symbol = "DCASH";
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
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

    function balanceOf(address _owner) view public returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender)
    view public returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    // mapping (address => uint256) balances;  -- removed as now provided in base contract
    // mapping (address => mapping (address => uint256)) allowed; -- moved to earlier to prevent clash
}
