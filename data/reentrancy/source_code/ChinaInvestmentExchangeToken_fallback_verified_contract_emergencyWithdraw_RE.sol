/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First calling initiateEmergencyWithdraw() to set up the emergency withdrawal state, 2) Waiting for the time delay, 3) Then calling emergencyWithdraw() which makes an external call before updating state. An attacker can exploit this by having their fallback function recursively call emergencyWithdraw() before the state is updated, draining more tokens than they should be able to withdraw. The vulnerability is stateful because it depends on the emergencyMode and emergencyWithdrawals mappings persisting between transactions.
 */
// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
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

/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/


contract ChinaInvestmentExchangeToken is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    // === FALLBACK INJECTION: Reentrancy ===
    // Emergency withdrawal system - allows users to withdraw funds in case of emergency
    mapping (address => uint256) public emergencyWithdrawals;
    mapping (address => bool) public emergencyMode;
    uint256 public emergencyWithdrawDelay = 24 hours;
    mapping (address => uint256) public emergencyWithdrawTime;

    function initiateEmergencyWithdraw(uint256 _amount) public returns (bool) {
        require(balances[msg.sender] >= _amount);
        require(!emergencyMode[msg.sender]);
        
        emergencyWithdrawals[msg.sender] = _amount;
        emergencyWithdrawTime[msg.sender] = block.timestamp;
        emergencyMode[msg.sender] = true;
        
        return true;
    }

    function emergencyWithdraw() public returns (bool) {
        require(emergencyMode[msg.sender]);
        require(block.timestamp >= emergencyWithdrawTime[msg.sender] + emergencyWithdrawDelay);
        
        uint256 amount = emergencyWithdrawals[msg.sender];
        require(balances[msg.sender] >= amount);
        
        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(amount * 1 wei)()) {
            balances[msg.sender] -= amount;
            emergencyWithdrawals[msg.sender] = 0;
            emergencyMode[msg.sender] = false;
            
            Transfer(msg.sender, address(0), amount);
            return true;
        }
        
        return false;
    }
    // === END FALLBACK INJECTION ===

    function ChinaInvestmentExchangeToken(
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
