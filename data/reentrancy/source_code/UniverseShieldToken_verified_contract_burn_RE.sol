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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a burn notification system with external callbacks. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: Added `pendingBurns` mapping to track burn operations across transactions
 * 2. **External Call Before State Update**: The `onBurnInitiated` callback occurs before balance updates, violating checks-effects-interactions pattern
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker calls burn() with malicious contract
 *    - During callback, malicious contract can call other functions that rely on the unchanged balanceOf state
 *    - Transaction 2+: Attacker can exploit accumulated state changes from pendingBurns tracking
 *    - The vulnerability becomes more severe with repeated exploitation across multiple transactions
 * 
 * 4. **Realistic Integration**: The burn notification system is a common pattern in DeFi protocols where external contracts need to be notified of token supply changes
 * 
 * The vulnerability is stateful because `pendingBurns` state persists between transactions, and multi-transaction because the full exploitation requires building up state over multiple function calls to maximize impact.
 */
pragma solidity ^0.4.11;

contract UniverseShieldToken {

    string public name = "Universe Shield Token";      //  token name
    string public symbol = "UST";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000;
    address owner = 0x0;

    // Added variable declarations
    mapping(address => uint256) public pendingBurns;
    address public burnNotificationContract;
    
    // Interface for burn notification contract
    // Moved interface IBurnNotification outside the contract definition
}

interface IBurnNotification {
    function onBurnInitiated(address sender, uint256 value) external;
}

contract UniverseShieldTokenCont is UniverseShieldToken {
    // Inherit all functions and variables
}

// Re-added the entire contract content below, without re-declaring the IBurnNotification interface.
contract UniverseShieldTokenFixed {
    string public name = "Universe Shield Token";
    string public symbol = "UST";
    uint256 public decimals = 6;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000;
    address owner = 0x0;

    mapping(address => uint256) public pendingBurns;
    address public burnNotificationContract;

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

    function UniverseShieldTokenFixed(address _addressFounder) public {
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

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending burn operations for multi-transaction exploitation
        pendingBurns[msg.sender] += _value;
        
        // VULNERABILITY: External call before state update enables reentrancy
        // This allows malicious contracts to manipulate state during callback
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurnInitiated(msg.sender, _value);
        }
        
        // State updates happen after external call (violates checks-effects-interactions)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Complete the burn operation
        pendingBurns[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
