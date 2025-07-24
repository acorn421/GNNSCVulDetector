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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Split State Updates**: Separated the balance deduction and addition operations, placing an external call between them
 * 2. **External Call Injection**: Added a callback to `ITokenReceiver(_to).onTokenReceived()` after deducting from sender but before adding to recipient
 * 3. **Partial State Vulnerability**: Created a window where sender's balance is reduced but recipient's balance is not yet increased
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker deploys malicious contract implementing `ITokenReceiver`
 * - Attacker obtains some tokens in their EOA account
 * 
 * **Transaction 2 (First Transfer - Trigger):**
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - Function deducts tokens from attacker's EOA balance
 * - External call triggers `onTokenReceived()` in malicious contract
 * - Malicious contract re-enters `transfer()` with remaining EOA balance
 * 
 * **Transaction 3+ (Reentrancy Chain):**
 * - Each reentrant call further reduces EOA balance without increasing recipient balance
 * - State inconsistency accumulates across multiple nested calls
 * - Attacker can drain more tokens than originally owned
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on accumulated state changes from multiple function calls
 * 2. **Nested Call Dependency**: Each reentrant call builds upon the state modifications of previous calls
 * 3. **Gradual Balance Manipulation**: The exploit requires a sequence of balance deductions without corresponding additions
 * 4. **Cross-Call State Persistence**: The inconsistent state persists between function calls, enabling progressive exploitation
 * 
 * The vulnerability is stateful (relies on persistent balance state) and multi-transaction (requires nested function calls in sequence), making it suitable for security research datasets focusing on complex, realistic attack patterns.
 */
pragma solidity ^0.4.22;

contract WinstexToken {

    string public name = "WINSTEX";
    string public symbol = "WIN";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 968000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    // Moved ITokenReceiver interface OUTSIDE contract for Solidity 0.4.x compatibility
}

// ITokenReceiver interface definition outside the contract
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external;
}

contract WinstexToken2 is WinstexToken {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Deduct tokens from sender first
        balanceOf[msg.sender] -= _value;
        
        // External call to recipient before completing state updates (reentrancy vector)
        if (_to.delegatecall.selector != bytes4(0)) { // fixes using code property that does not exist in 0.4.22
            ITokenReceiver(_to).onTokenReceived(msg.sender, _value);
        }
        
        // Complete the transfer by adding tokens to recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
