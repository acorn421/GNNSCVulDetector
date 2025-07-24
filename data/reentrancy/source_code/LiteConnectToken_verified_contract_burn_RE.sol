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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn reward contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnReward(burnRewardContract).onBurn(msg.sender, _value)` after the balance check but before state updates
 * 2. The external call occurs when `burnRewardContract` is set to a non-zero address
 * 3. State modifications (balance updates) happen after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn()` with value X
 *    - Balance check passes (user has X tokens)
 *    - External call to malicious reward contract triggers
 *    - Malicious contract re-enters `burn()` with same value X
 *    - Second call's balance check still passes (balance not yet updated)
 *    - Both calls proceed to update state, causing double burning
 * 
 * 2. **Transaction 2**: Attacker repeats the process to accumulate more exploited burns
 *    - Each transaction can trigger multiple re-entrant calls
 *    - State persists between transactions, allowing repeated exploitation
 *    - The vulnerability compounds across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent state of `balanceOf` mapping between transactions
 * - Each transaction can be exploited independently, but the full impact requires multiple transactions
 * - The attacker needs to set up the malicious reward contract first, then exploit in subsequent transactions
 * - The exploitation effect accumulates across multiple burn transactions
 * - Gas limits prevent infinite reentrancy in a single transaction, making multi-transaction exploitation necessary for maximum impact
 * 
 * **State Persistence Requirements:**
 * - The `balanceOf` mapping maintains state between transactions
 * - The `burnRewardContract` address must be set in a previous transaction
 * - Each successful exploitation reduces the total supply incorrectly, persisting the effect
 * - The vulnerability creates a permanent inconsistency in token accounting that compounds over time
 */
pragma solidity ^0.4.11;

contract LiteConnectToken {

    string public name = "LiteConnet";      //  token name
    string public symbol = "LCC";           //  token symbol
    uint256 public decimals = 0;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    address[] addresses;
    uint[] values;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 28000000;
    address owner = 0x0;

    // Declaration for reentrancy vulnerability
    address public burnRewardContract = address(0);

    // Moved IBurnReward interface outside the contract
}

// Minimal IBurnReward interface must be declared outside contract in Solidity <0.5
interface IBurnReward {
    function onBurn(address _burner, uint256 _value) external;
}

contract LiteConnectTokenCore is LiteConnectToken {
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

    function LiteConnectToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn reward contract before state updates
        if (burnRewardContract != address(0)) {
            IBurnReward(burnRewardContract).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    function Distribute(address[] _addresses, uint256[] _values) public payable returns(bool){
        for (uint i = 0; i < _addresses.length; i++) {
            transfer(_addresses[i], _values[i]);
        }
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}