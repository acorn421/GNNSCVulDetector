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
 * **Specific Changes Made:**
 * 1. Added a contract detection check using `_to.code.length > 0` to identify contract recipients
 * 2. Introduced an external call to the recipient contract using `onTokenReceived` callback mechanism
 * 3. Used low-level assembly call to avoid reverting on callback failure, maintaining function flow
 * 4. Positioned the external call AFTER all state updates but BEFORE the Transfer event
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract with `onTokenReceived` callback
 * - Victim approves the malicious contract to spend tokens via `approve(attackerContract, largeAmount)`
 * - This creates persistent state: `allowance[victim][attackerContract] = largeAmount`
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `transferFrom(victim, attackerContract, amount)` 
 * - State updates occur: balances and allowances are modified
 * - The malicious contract's `onTokenReceived` callback is triggered
 * - Inside the callback, the attacker can call `transferFrom` again since allowance still shows remaining balance
 * - This creates a reentrancy loop where multiple transfers can occur before the original call completes
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Accumulation**: The vulnerability requires pre-existing allowance state set in a previous transaction
 * 2. **Contract Deployment**: The malicious recipient contract must be deployed and positioned beforehand
 * 3. **Approval Mechanism**: The ERC20 approval system inherently requires a separate transaction to set allowances
 * 4. **Callback Preparation**: The attacker needs to prepare the malicious contract's callback logic in advance
 * 
 * **Exploitation Flow:**
 * ```
 * Tx1: victim.approve(attackerContract, 1000)
 * Tx2: attackerContract.triggerExploit() →
 *      - Calls transferFrom(victim, attackerContract, 100)
 *      - State updated: victim balance -= 100, attacker balance += 100, allowance -= 100
 *      - onTokenReceived callback triggered
 *      - Callback calls transferFrom(victim, attackerContract, 100) again
 *      - Reentrancy allows multiple transfers before original call completes
 * ```
 * 
 * This vulnerability is realistic because recipient notifications are common in modern token standards, and the stateful nature of allowances combined with the callback mechanism creates a genuine multi-transaction reentrancy attack vector.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-30
*/

pragma solidity ^0.4.22;

contract Natterix {

    string public name = "Natterix";
    string public symbol = "NRX";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 500000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor() public {
        owner = msg.sender;
        adminWallet = owner;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer if it's a contract
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            bytes memory payload = abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value);
            bool callSuccess;
            assembly {
                callSuccess := call(gas, _to, 0, add(payload, 0x20), mload(payload), 0, 0)
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function setSymbol(string _symbol) public isOwner {
        symbol = _symbol;
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
