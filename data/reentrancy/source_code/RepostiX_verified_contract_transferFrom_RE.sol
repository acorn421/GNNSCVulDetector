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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a callback mechanism that calls `onTokenReceived` on the recipient contract if it has code
 * 2. **Violated Checks-Effects-Interactions**: The external call occurs after balance updates but before allowance reduction
 * 3. **State Persistence**: Balance changes persist while allowance remains temporarily unchanged during the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves themselves a large allowance from victim's account
 * - Attacker deploys a malicious contract as the recipient (`_to`)
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - Function updates balances: `balanceOf[victim] -= amount`, `balanceOf[maliciousContract] += amount`
 * - External call triggers `maliciousContract.onTokenReceived()`
 * - During callback, malicious contract calls `transferFrom` again with same parameters
 * - The reentrant call sees updated balances but unchanged allowance
 * - This creates inconsistent state that persists between transactions
 * 
 * **Transaction 3 (Exploitation):**
 * - Attacker leverages the inconsistent state from previous transactions
 * - Can manipulate allowance calculations or balance checks
 * - The accumulated state changes from multiple reentrant calls enable fund extraction
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: Balance and allowance state persists between transactions, creating opportunities for stateful attacks
 * 2. **Allowance Accumulation**: The vulnerability requires building up allowance manipulation across multiple calls
 * 3. **Complex State Dependencies**: The exploit relies on the relationship between balance updates and allowance reductions happening at different times
 * 4. **Reentrancy Guard Absence**: Without proper reentrancy protection, each transaction can modify state that affects subsequent transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * This represents a common real-world vulnerability where token contracts add recipient notifications without proper reentrancy protection, creating stateful vulnerabilities that require multiple transactions to fully exploit.
 */
pragma solidity ^0.4.11;

contract RepostiX   {

    string public name = "RepostiX";      //  token name
    string public symbol = "REPX";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 21000000000000000;
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

    function RepostiX(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable: External call to recipient before allowance update
        // This enables stateful reentrancy across multiple transactions
        if (isContract(_to)) {
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            // Ignore return value for pre-0.5.0
            _to.call(abi.encodeWithSelector(selector, _from, _to, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
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

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Helper to detect if address is contract (for pre-0.5.0)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
