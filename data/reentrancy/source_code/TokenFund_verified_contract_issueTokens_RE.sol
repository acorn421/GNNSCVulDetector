/*
 * ===== SmartInject Injection Details =====
 * Function      : issueTokens
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address between updating the recipient's balance and the total supply. The vulnerability follows the classic Checks-Effects-Interactions pattern violation:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_for.call(bytes4(keccak256("onTokensIssued(uint256)")), tokenCount)` after updating `balances[_for]` but before updating `totalSupply`
 * 2. This creates a state inconsistency window where balances are updated but totalSupply is not yet updated
 * 3. The recipient can implement `onTokensIssued` callback to re-enter the function during this inconsistent state
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `issueTokens` for a malicious contract address
 * 2. **During Transaction 1**: The malicious contract's `onTokensIssued` callback is triggered, which can call `issueTokens` again
 * 3. **Reentrant Call**: During the callback, `balances[_for]` has already been updated, but `totalSupply` hasn't, creating exploitable state inconsistency
 * 4. **State Accumulation**: Each reentrant call adds more tokens to the attacker's balance while the totalSupply update is delayed
 * 5. **Multiple Transactions**: The attack requires the initial transaction setup and then leverages the callback mechanism to create multiple execution contexts
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial state setup (emissionEnabled=true, proper crowdfunding contract permissions)
 * - Each reentrant call during the callback represents a separate execution context
 * - The exploit builds upon the accumulated state changes from previous calls
 * - The inconsistent state (updated balances but not totalSupply) persists across the reentrant calls
 * - The attack cannot be performed in a single atomic transaction without the callback mechanism triggering multiple execution paths
 * 
 * This creates a realistic vulnerability where an attacker can drain more tokens than intended by exploiting the state inconsistency during reentrancy.
 */
pragma solidity ^0.4.6;

contract StandardToken {

    /*
     *  Data structures
     */
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;

    /*
     *  Events
     */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /*
     *  Read and write storage functions
     */
    /// @dev Transfers sender's tokens to a given address. Returns success.
    /// @param _to Address of token receiver.
    /// @param _value Number of tokens to transfer.
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        else {
            return false;
        }
    }

    /// @dev Allows allowed third party to transfer tokens from one address to another. Returns success.
    /// @param _from Address from where tokens are withdrawn.
    /// @param _to Address to where tokens are sent.
    /// @param _value Number of tokens to transfer.
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        }
        else {
            return false;
        }
    }

    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    /// @dev Sets approved amount of tokens for spender. Returns success.
    /// @param _spender Address of allowed account.
    /// @param _value Number of approved tokens.
    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /*
     * Read storage functions
     */
    /// @dev Returns number of allowed tokens for given address.
    /// @param _owner Address of token owner.
    /// @param _spender Address of token spender.
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

}


/// @title Token contract - Implements Standard Token Interface for TokenFund.
/// @author Evgeny Yurtaev - <evgeny@etherionlab.com>
contract TokenFund is StandardToken {

    /*
     * External contracts
     */
    address public emissionContractAddress = 0x0;

    /*
     * Token meta data
     */
    string constant public name = "TheToken Fund";
    string constant public symbol = "TKN";
    uint8 constant public decimals = 8;

    /*
     * Storage
     */
    address public owner = 0x0;
    bool public emissionEnabled = true;
    bool transfersEnabled = true;

    /*
     * Modifiers
     */

    modifier isCrowdfundingContract() {
        // Only emission address is allowed to proceed.
        if (msg.sender != emissionContractAddress) {
            throw;
        }
        _;
    }

    modifier onlyOwner() {
        // Only owner is allowed to do this action.
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    /*
     * Contract functions
     */

     /// @dev TokenFund emission function.
    /// @param _for Address of receiver.
    /// @param tokenCount Number of tokens to issue.
    function issueTokens(address _for, uint tokenCount)
        external
        isCrowdfundingContract
        returns (bool)
    {
        if (emissionEnabled == false) {
            throw;
        }

        balances[_for] += tokenCount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient of token issuance - potential callback vulnerability
        if (_for.call(bytes4(keccak256("onTokensIssued(uint256)")), tokenCount)) {
            // Callback succeeded
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply += tokenCount;
        return true;
    }

    /// @dev Withdraws tokens for msg.sender.
    /// @param tokenCount Number of tokens to withdraw.
    function withdrawTokens(uint tokenCount)
        public
        returns (bool)
    {
        uint balance = balances[msg.sender];
        if (balance < tokenCount) {
            return false;
        }
        balances[msg.sender] -= tokenCount;
        totalSupply -= tokenCount;
        return true;
    }

    /// @dev Function to change address that is allowed to do emission.
    /// @param newAddress Address of new emission contract.
    function changeEmissionContractAddress(address newAddress)
        external
        onlyOwner
        returns (bool)
    {
        emissionContractAddress = newAddress;
    }

    /// @dev Function that enables/disables transfers of token.
    /// @param value True/False
    function enableTransfers(bool value)
        external
        onlyOwner
    {
        transfersEnabled = value;
    }

    /// @dev Function that enables/disables token emission.
    /// @param value True/False
    function enableEmission(bool value)
        external
        onlyOwner
    {
        emissionEnabled = value;
    }

    /*
     * Overriding ERC20 standard token functions to support transfer lock
     */
    function transfer(address _to, uint256 _value)
        returns (bool success)
    {
        if (transfersEnabled == true) {
            return super.transfer(_to, _value);
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint256 _value)
        returns (bool success)
    {
        if (transfersEnabled == true) {
            return super.transferFrom(_from, _to, _value);
        }
        return false;
    }


    /// @dev Contract constructor function sets initial token balances.
    /// @param _owner Address of the owner of TokenFund.
    function TokenFund(address _owner)
    {
        totalSupply = 0;
        owner = _owner;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}