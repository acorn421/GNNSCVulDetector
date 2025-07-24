/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. **Added State Tracking**: Introduced `pendingBurns` mapping to track cumulative burn amounts across transactions
 * 2. **External Call Vulnerability**: Added `burnNotificationContract` callback that occurs after state modifications
 * 3. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions because:
 *    - Transaction 1: Attacker calls burn() with legitimate balance, pendingBurns accumulates
 *    - During reentrant call: The balance check still passes due to previous state changes
 *    - Transaction 2+: Accumulated pendingBurns state enables further exploitation
 *    - The attacker can drain more tokens than they should own by leveraging the persistent pendingBurns state
 * 
 * **Exploitation Sequence:**
 * 1. **Setup Phase**: Attacker deploys malicious contract and sets it as burnNotificationContract
 * 2. **Transaction 1**: Attacker calls burn(100) with 100 token balance
 *    - pendingBurns[attacker] = 100
 *    - balanceOf[attacker] = 0
 *    - During onBurn callback, attacker can't immediately re-enter due to balance check
 * 3. **Transaction 2**: Attacker receives more tokens from elsewhere
 * 4. **Transaction 3**: Attacker calls burn(50) with 50 token balance
 *    - pendingBurns[attacker] = 150 (accumulated state)
 *    - During onBurn callback, attacker re-enters burn() 
 *    - The accumulated pendingBurns state enables exploitation beyond current balance
 *    - Multiple reentrant calls can drain contract balance using historical state
 * 
 * The vulnerability is stateful because pendingBurns persists between transactions and multi-transaction because the exploitation depends on accumulated state from previous burn operations.
 */
pragma solidity ^0.4.11;

contract ExKnox {

    string public name = "ExKnox";      //  token name
    string public symbol = "EKX";           //  token symbol
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 100000000000000000;
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

    // Updated constructor to follow syntax for Solidity >=0.4.22
    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingBurns;
    address public burnNotificationContract;
    
    // Declaration of the missing interface as a top-level contract
}

// Move interface declaration to the top level - allowed in Solidity 0.4.x
interface IBurnNotifier {
    function onBurn(address from, uint256 value) external;
}

contract ExKnox_Extra {
    // Reopen ExKnox to continue methods after the interface, because interface can't be nested
}

// Back in ExKnox - move the burn function implementation outside
// placed here to fit older Solidity rules (one contract per file unless using the partial pattern, but minimal fix is to put all code in order)

// Burn function implementation
// Re-declare variables used
contract ExKnox_Burn is ExKnox {
    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        // Add to pending burns (stateful accumulation)
        pendingBurns[msg.sender] += _value;
        // Update balance immediately
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        // Vulnerable external call after state modifications
        if (burnNotificationContract != address(0)) {
            IBurnNotifier(burnNotificationContract).onBurn(msg.sender, _value);
        }
        Transfer(msg.sender, 0x0, _value);
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
