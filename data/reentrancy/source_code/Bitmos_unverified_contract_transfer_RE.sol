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
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` callback after balance updates
 * 2. The call is made AFTER state changes but BEFORE the Transfer event
 * 3. Execution continues regardless of callback success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls transfer() to malicious contract, which receives callback and can call transfer() again, but with limited impact due to reduced balance
 * 2. **Transaction 2**: Attacker prepares by accumulating tokens across multiple addresses or setting up complex state
 * 3. **Transaction 3+**: Attacker executes coordinated multi-contract attack where:
 *    - Contract A transfers to Contract B (triggers callback)
 *    - Contract B's callback transfers to Contract C (triggers another callback)
 *    - Contract C's callback can manipulate state or trigger additional transfers
 *    - The vulnerability compounds across multiple transactions as state changes persist
 * 
 * **Why Multi-Transaction Requirement:**
 * - Single transaction reentrancy is limited by the sender's balance after the first deduction
 * - Multi-transaction exploitation allows attackers to:
 *   - Accumulate tokens across multiple addresses beforehand
 *   - Set up complex contract networks that trigger cascading callbacks
 *   - Exploit the persistent state changes from previous transactions
 *   - Bypass balance checks through coordinated timing across multiple transactions
 * - The stateful nature means each transaction's state changes persist, enabling cumulative exploitation
 * 
 * **Exploitation Method:**
 * The attacker can create a network of contracts that, across multiple transactions:
 * 1. Build up token balances in preparation
 * 2. Execute coordinated transfers that trigger callbacks
 * 3. Use callbacks to manipulate state while the original transfer is still executing
 * 4. Compound the effects across multiple transactions to drain more tokens than should be possible
 * 
 * This creates a realistic vulnerability where the external call enables reentrancy, but the real exploitation requires careful orchestration across multiple transactions to be effective.
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


contract Bitmos is EIP20Interface {

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

    // Vulnerable transfer function with reentrancy vulnerability present
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract - creates reentrancy vulnerability
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            (bool callSuccess, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    //송신자(_from)주소에서 수신자(_to) 주소로 해당금액(_value)을 송금. 송금이 성공하면 TRUE를 반환하고, 실패하면 FALSE를 반환.
    //transferFrom이 성공하려면 먼저 approve 인터페이스를 사용하여 일정금액을 인출할수 있도록 허락하여야 함.
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

    //owner가 보유한 토큰잔액을 반환
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    //송신자(msg.sender)가 보유한 토큰에서 일정금액(_value)만큼의 토큰을 인출할수 있는 권한을 수신자(_spender)에게 부여.
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    //토큰 소유자(_owner)가 토큰 수신자(_spender)에게 인출을 허락한 토큰이 얼마인지를 반환.
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
