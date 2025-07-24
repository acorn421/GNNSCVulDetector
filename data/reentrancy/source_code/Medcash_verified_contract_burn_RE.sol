/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added persistent state tracking**: Added `pendingBurns` mapping to track burn operations across transactions
 * 2. **Inserted external call before state updates**: Added callback to user-controlled contract that violates Checks-Effects-Interactions pattern
 * 3. **Created stateful exploitation window**: The pendingBurns state persists between transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls burn() with amount X
 * - pendingBurns[attacker] = X (state persists)
 * - External callback triggers, but attacker doesn't exploit yet
 * - Balance is reduced normally
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls burn() again with amount Y
 * - pendingBurns[attacker] = X + Y (accumulated state)
 * - In the callback, attacker can see they have X + Y pending burns
 * - Attacker can re-enter burn() function during callback
 * - Since balanceOf updates happen after external call, attacker can exploit the state inconsistency
 * - The accumulated pendingBurns state enables the attacker to calculate optimal re-entry amounts
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires accumulated state in pendingBurns mapping
 * - Attacker needs to build up pending burn amounts across multiple calls
 * - The exploitation depends on the persistent state that spans multiple transactions
 * - Single transaction exploitation is not possible due to the need for state accumulation
 * 
 * The vulnerability is stateful because it depends on the pendingBurns mapping that persists between transactions, and multi-transaction because the exploitation requires building up state across multiple function calls.
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

    function Medcash(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // State variable to track pending burns across transactions
    mapping(address => uint256) public pendingBurns;
    
    // Declare the burnCallback variable
    address public burnCallback;

    // Interface for burn callback
    // Moved interface declaration outside the contract
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending burns before external call
        pendingBurns[msg.sender] += _value;
        
        // External call to user-controlled contract before state updates
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onBurnInitiated(msg.sender, _value);
        }
        
        // State updates occur after external call - vulnerability window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burns after successful burn
        pendingBurns[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// ===== Moved interface definition outside contract for Solidity <0.5.0 compatibility =====
interface IBurnCallback {
    function onBurnInitiated(address from, uint256 value) external;
}
