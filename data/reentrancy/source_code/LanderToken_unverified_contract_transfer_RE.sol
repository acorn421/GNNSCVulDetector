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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract's `onTokenReceived` function before state updates
 * 2. Moved balance updates to occur AFTER the external call
 * 3. Added recipient contract detection using `_to.code.length > 0`
 * 4. Used low-level call to maintain compatibility with any recipient contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract that implements `onTokenReceived`
 * 2. **Transaction 2**: Victim calls `transfer()` to send tokens to attacker's contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` is called before state updates
 * 4. **Reentrant Call**: Malicious contract calls `transfer()` again with the same tokens (balance hasn't been updated yet)
 * 5. **Transaction 3+**: Attacker can repeat this process across multiple transactions to drain funds
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability relies on the attacker having a deployed contract (Transaction 1)
 * - Each exploitation requires a separate transaction from victims
 * - The attacker needs to accumulate stolen tokens across multiple victim transactions
 * - The full impact is realized through repeated exploitation across multiple blocks/transactions
 * - State persistence between transactions allows the attacker to build up stolen balances over time
 * 
 * **State Persistence:**
 * - The `balances` mapping persists between transactions
 * - Each successful reentrancy attack updates the global state
 * - Accumulated stolen tokens remain in attacker's balance across transactions
 * - Multiple victims can be exploited in sequence, with effects accumulating
 * 
 * This creates a realistic vulnerability where the attacker must: deploy a contract, wait for victims to transfer tokens, and exploit the reentrancy across multiple separate transactions to maximize the attack impact.
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

contract LanderToken is EIP20Interface {
    address owner = msg.sender;

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
    uint price;

    // Vulnerable transfer function (reentrancy)
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable external call before state updates
        if (isContract(_to)) {
            // Call to recipient contract's onTokenReceived function
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Recipient callback failed");
        }
        
        // State updates occur AFTER external call - classic reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Helper for contract detection (since .code is not available in Solidity 0.4.x)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    // Constructor (use constructor syntax for Solidity >=0.4.22, but keep function for 0.4.18)
    function LanderToken(
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
    /* function() public payable{
        if (price >=0 ether){
        uint toMint = 1000;
       
        totalSupply -= toMint;
        if (totalSupply>=6000000){
        balances[msg.sender] += toMint;
        Transfer(0,msg.sender, toMint);
        }
        if (totalSupply<6000000){
        throw;
        }
        }
        
       owner.transfer(msg.value);

     }
       */
       
}
