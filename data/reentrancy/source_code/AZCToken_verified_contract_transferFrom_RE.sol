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
 * **Key Changes Made:**
 * 1. **External Call Addition**: Added a callback to the recipient contract (`_to.call(...)`) that occurs after the recipient's balance is updated but before the sender's balance and allowance are decremented.
 * 
 * 2. **State Update Reordering**: Moved the sender's balance deduction and allowance reduction to occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Dependency**: The vulnerability requires multiple transactions because:
 *    - Transaction 1: Attacker must first obtain approval (via `approve()`) to spend tokens
 *    - Transaction 2: Initial `transferFrom` call triggers the vulnerability
 *    - Transaction 3+: Reentrant calls exploit the inconsistent state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase** (Transaction 1): Attacker gets approval to spend victim's tokens
 * 2. **Initial Call** (Transaction 2): Attacker calls `transferFrom()` to their malicious contract
 * 3. **Reentrancy Window**: The malicious contract receives `onTokenReceived()` callback when recipient balance is updated but sender balance/allowance are not yet decremented
 * 4. **Exploitation** (Transaction 3+): Malicious contract can make additional `transferFrom()` calls using the same allowance before it gets decremented, since the original call hasn't finished updating all state variables
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single atomic transaction because the attacker needs to first establish the allowance relationship
 * - The reentrant calls depend on the persistent state from the initial transaction (allowance still being available)
 * - Each reentrant call creates a new transaction context, accumulating the exploitation across multiple blockchain transactions
 * - The attack window exists between the recipient balance update and the allowance deduction, which persists across transaction boundaries
 * 
 * This creates a realistic vulnerability where an attacker can drain more tokens than they should be allowed to by exploiting the state inconsistency window that exists across multiple transaction calls.
 */
pragma solidity ^0.4.11;

contract AZCToken {

    string public name = "AZC";
    string public symbol = "AZC";
    uint256 public decimals = 8;
    string public constant PRICE_PRESALE = "$0.1";
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant TOKEN_SUPPLY_TOTAL = 20000000000000000;
    uint public tokensIssuedIco = 14000000000000000;
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

    constructor(address _addressFounder) public {
        owner = msg.sender;
        adminWallet = owner;
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

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // External call to recipient before completing state changes
        // This enables multi-transaction reentrancy attacks
        if (_isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        
        // State changes occur after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function _isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
