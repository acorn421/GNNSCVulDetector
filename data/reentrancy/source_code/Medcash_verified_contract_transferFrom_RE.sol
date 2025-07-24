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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance reduction. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added contract detection check: `if (_to.code.length > 0)`
 * 2. Inserted external call: `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value)`
 * 3. Moved the external call between balance updates and allowance reduction
 * 4. Added require statement for call success to make it appear legitimate
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Legitimate user calls transferFrom() to transfer tokens to malicious contract
 *    - Balance updates occur (balanceOf[_to] += _value, balanceOf[_from] -= _value)
 *    - External call is made to malicious contract's onTokenReceived function
 *    - Allowance is reduced after the call returns
 *    
 * 2. **Transaction 2**: Malicious contract's onTokenReceived function executes in separate transaction context
 *    - Contract can call transferFrom again using the same allowance
 *    - Since allowance reduction happened in previous transaction, the check passes
 *    - This enables double-spending or drain attacks across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability leverages the fact that external calls can trigger callbacks in separate transaction contexts
 * - State changes from the first transaction (balance updates) persist and enable exploitation in subsequent callback transactions
 * - The allowance reduction occurs after the external call, creating a window where the same allowance can be used multiple times across different transaction boundaries
 * - Single-transaction exploitation is prevented by the gas limits and transaction atomicity, but multi-transaction exploitation is possible through callback mechanisms
 * 
 * This creates a realistic vulnerability that mirrors real-world reentrancy issues in token contracts with callback mechanisms.
 */
pragma solidity ^0.4.17;

contract Medcash {

    string public name = "Medcash";      //  token name
    string public symbol = "MEDCASH";           //  token symbol
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 20000000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
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
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract (common pattern for token callbacks)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call before allowance reduction - creates reentrancy window
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
