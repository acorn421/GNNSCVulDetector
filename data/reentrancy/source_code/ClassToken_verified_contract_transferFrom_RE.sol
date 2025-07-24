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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and gets approval to spend tokens from a victim account
 * 2. **Exploitation Phase (Transaction 2)**: Attacker calls transferFrom() to transfer tokens to their malicious contract
 * 3. **Reentrancy Phase (Within Transaction 2)**: The malicious contract's onTokenReceived() callback re-enters transferFrom() before the original call completes its state updates
 * 
 * **Key Vulnerability Details:**
 * 
 * - **State Persistence**: The balanceOf[_to] is updated before the external call, but balanceOf[_from] and allowance are updated after
 * - **Multi-Transaction Dependency**: Requires prior approval (separate transaction) and the exploitation happens during the transfer call
 * - **Reentrancy Window**: Between the external call and the remaining state updates, the contract is in an inconsistent state where:
 *   - Recipient balance is already increased
 *   - Sender balance is not yet decreased
 *   - Allowance is not yet decreased
 *   
 * - **Exploitation**: During reentrancy, the malicious contract can call transferFrom() again with the same parameters, bypassing the allowance check since it hasn't been decremented yet, effectively allowing multiple transfers with a single approval
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The attack requires a pre-existing approval (first transaction)
 * 2. The external call and reentrancy happen within the transfer transaction (second transaction)
 * 3. The vulnerability depends on state accumulated from the approval transaction
 * 4. Multiple reentrant calls within the same transaction can compound the effect due to persistent state inconsistencies
 * 
 * This creates a realistic vulnerability where the external call notification feature introduces a reentrancy risk that allows draining more tokens than approved.
 */
pragma solidity ^0.4.11;

contract ClassToken {

    string public name = "ClassToken";      //  token name
    string public symbol = "CTC";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 5*10**26;
    address owner = 0x16D6234c2FBBEf7B7Bea8a7B181825daA4E5B56D;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(owner != msg.sender);
        _;
    }

    // Changed deprecated constructor style to proper constructor syntax
    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(owner, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update recipient balance first
        balanceOf[_to] += _value;
        // In Solidity 0.4.x, address does not have 'code'. Use extcodesize instead
        uint256 size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            // Use low-level call (Solidity 0.4.x style)
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue execution regardless of call result
        }
        // State updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[owner] += _value;
        emit Transfer(msg.sender, owner, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}