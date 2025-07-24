/*
 * ===== SmartInject Injection Details =====
 * Function      : issueTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent token emission system with accumulated time bonuses. The vulnerability creates a stateful, multi-transaction exploit where:
 * 
 * 1. **State Variables Added**: The function now relies on two persistent state variables:
 *    - `lastEmissionTime`: Tracks the timestamp of the last token emission
 *    - `accumulatedTimeBonus`: Accumulates bonus percentage over time (persists between transactions)
 * 
 * 2. **Timestamp Dependency**: The function uses `block.timestamp` to calculate time differences and determine bonus multipliers, making it vulnerable to miner timestamp manipulation.
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls `issueTokens()` to establish initial `lastEmissionTime`
 *    - **Time Manipulation**: Miner manipulates `block.timestamp` in subsequent blocks
 *    - **Transaction 2+**: Attacker calls `issueTokens()` again to exploit inflated time differences, receiving excessive bonus tokens
 * 
 * 4. **Stateful Accumulation**: The `accumulatedTimeBonus` persists and grows across transactions, allowing attackers to build up massive bonuses through repeated timestamp manipulation.
 * 
 * 5. **Realistic Scenario**: This mimics real-world crowdfunding contracts that offer early-bird bonuses or time-based incentives, making the vulnerability realistic and subtle.
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial state must be established (lastEmissionTime = 0 check)
 * - Time accumulation happens between transactions
 * - Bonus calculation depends on persistent state from previous calls
 * - Maximum exploitation requires coordinated timestamp manipulation across multiple blocks
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
    uint256 public lastEmissionTime = 0;
    uint256 public accumulatedTimeBonus = 0;

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

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based emission rate limiting with accumulated bonus
        if (lastEmissionTime == 0) {
            lastEmissionTime = block.timestamp;
            accumulatedTimeBonus = 0;
        }
        
        // Calculate time-based bonus multiplier (1% per hour since last emission)
        uint256 timeDiff = block.timestamp - lastEmissionTime;
        uint256 hoursPassed = timeDiff / 3600; // 3600 seconds = 1 hour
        
        // Accumulate time bonus across transactions (caps at 50%)
        if (hoursPassed > 0) {
            accumulatedTimeBonus += hoursPassed;
            if (accumulatedTimeBonus > 50) {
                accumulatedTimeBonus = 50;
            }
            lastEmissionTime = block.timestamp;
        }
        
        // Apply accumulated bonus to token issuance
        uint256 bonusTokens = (tokenCount * accumulatedTimeBonus) / 100;
        uint256 totalTokensToIssue = tokenCount + bonusTokens;

        balances[_for] += totalTokensToIssue;
        totalSupply += totalTokensToIssue;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        return true;
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
