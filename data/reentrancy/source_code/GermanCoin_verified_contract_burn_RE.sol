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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that allows external calls before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Deploy malicious contract implementing IBurnCallback
 * **Transaction 2 (Registration)**: Call setBurnCallback() to register the malicious contract
 * **Transaction 3+ (Exploitation)**: Call burn() which triggers the callback, allowing reentrancy
 * 
 * **Specific Changes Made:**
 * 1. Added external call to user-controlled contract (burnCallbacks[msg.sender]) before state updates
 * 2. The callback occurs after balance check but before balance modification (CEI pattern violation)
 * 3. Moved state modifications to occur after external calls
 * 
 * **Multi-Transaction Exploitation:**
 * - **Setup Phase**: Attacker deploys malicious contract with IBurnCallback.onBurn() that calls burn() recursively
 * - **Registration Phase**: Attacker calls setBurnCallback() to register their malicious contract
 * - **Exploitation Phase**: When burn() is called, the callback is triggered before balanceOf[msg.sender] is decremented
 * - **Reentrancy**: During the callback, the malicious contract can call burn() again while the original caller still has their full balance
 * - **State Accumulation**: Multiple reentrancy calls can burn more tokens than the user actually owns
 * 
 * **Why Multi-Transaction:**
 * - Requires separate transaction to set up callback registration (persistent state)
 * - Callback address must be stored in contract state between transactions
 * - Multiple burn calls can exploit the same callback registration across different transactions
 * - The vulnerability relies on accumulated state (callback registration) that persists between calls
 * 
 * This creates a realistic reentrancy vulnerability where the callback mechanism provides legitimate functionality but enables exploitation through the improper ordering of external calls and state updates.
 */
pragma solidity ^0.4.11;

contract GermanCoin {

    string public name = "GermanCoin";      //  token name
    string public symbol = "GCX";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 100000000000000000;
    address owner = 0x0;

    // Added definition for burnCallbacks
    mapping(address => address) public burnCallbacks;
    
    // Moved IBurnCallback outside contract, changed to contract (not interface)
}

// Moved outside main contract, used 'contract' instead of 'interface' for <=0.4.x
contract IBurnCallback {
    function onBurn(address _from, uint256 _value) external;
}

contract GermanCoinRest is GermanCoin {
    // inherit all - just for demonstration - not necessary
}

contract GermanCoinFixed is GermanCoin {
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

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (burnCallbacks[msg.sender] != address(0)) {
            IBurnCallback(burnCallbacks[msg.sender]).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

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
}
