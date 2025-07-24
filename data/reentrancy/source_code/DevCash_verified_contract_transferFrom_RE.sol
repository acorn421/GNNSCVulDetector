/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates but before allowance updates. This creates a window where the recipient contract can re-enter the transferFrom function with the same allowance, exploiting the fact that allowance is only decremented after the external call. The vulnerability requires: 1) Initial transaction to set up allowance, 2) Subsequent transferFrom call to malicious contract that re-enters during the callback, exploiting the persistent allowance state before it's decremented. This violates the Checks-Effects-Interactions pattern and enables multi-transaction exploitation patterns.
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


contract DevCash is EIP20Interface {

    uint256 constant MAX_UINT256 = 2**256 - 1;

    string public name;
    uint8 public decimals;
    string public symbol;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function DevCash() public {
        totalSupply = 21*10**8*10**8;               //DevCash totalSupply
        balances[msg.sender] = totalSupply;         //Allocate DevCash to contract deployer
        name = "DevCash";
        decimals = 8;                               //Amount of decimals for display purposes
        symbol = "DCASH";
    }

    // Vulnerable transferFrom with reentrancy (as required)
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of token receipt - VULNERABILITY INJECTION
        if(_to != address(0) && isContract(_to)) {
            bytes memory callData = abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value);
            bool callSuccess = _to.call(callData);
            require(callSuccess, "Token notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
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
}
