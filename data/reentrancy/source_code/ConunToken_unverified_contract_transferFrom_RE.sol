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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Inserted a call to `_to.call()` to notify the recipient contract about the incoming transfer, creating a reentrancy vector.
 * 
 * 2. **Violated Checks-Effects-Interactions**: Moved the external call to occur BEFORE critical state updates (sender balance reduction and allowance updates), allowing reentrant calls to see inconsistent state.
 * 
 * 3. **State Splitting**: The function now updates recipient balance first, then makes external call, then completes sender balance and allowance updates. This creates a vulnerable window where balances are inconsistent.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Attack Setup):**
 * - Attacker approves malicious contract to spend tokens
 * - Malicious contract calls transferFrom with victim as _from
 * - Function updates recipient balance (+value) 
 * - External call to malicious contract's onTokenReceived
 * - Malicious contract can now see: recipient has received tokens BUT sender balance not yet reduced
 * 
 * **Transaction 2+ (Reentrant Exploitation):**
 * - During the external call, malicious contract calls transferFrom again
 * - Second call sees sender still has original balance (not yet reduced)
 * - Passes balance/allowance checks using same allowance
 * - Updates recipient balance again (+value)
 * - Makes another external call (nested reentrancy)
 * - This can repeat multiple times before original call completes
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction reentrancy would be limited by gas and call stack depth
 * - The vulnerability accumulates state changes across multiple nested calls
 * - Each reentrant call builds upon the state inconsistencies from previous calls
 * - The attack requires setting up approvals in one transaction, then exploiting in subsequent reentrant calls
 * - Maximum exploitation requires the external call to trigger multiple reentrant transferFrom calls, each seeing the same "fresh" sender balance
 * 
 * **Stateful Nature:**
 * - Allowance state persists between calls and enables repeated exploitation
 * - Balance state accumulates incorrectly across multiple reentrant calls
 * - The vulnerability depends on the accumulated effect of multiple state modifications
 * - Each reentrant call depends on the state changes from previous calls in the sequence
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.18;

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

contract ConunToken is EIP20Interface {

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
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    // Keep the standard ERC20 transferFrom
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balances[_to] += _value;
        
        // Notify recipient of incoming transfer before completing state updates
        if (isContract(_to)) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of callback success
        }
        
        // Complete state updates after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   

    // Helper function to check if an address is a contract
    function isContract(address _addr) internal view returns (bool result) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
