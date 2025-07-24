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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback after state updates. The vulnerability requires:
 * 
 * 1. **Multi-Transaction Setup**: Attacker must deploy a malicious contract implementing IBurnCallback interface
 * 2. **State Accumulation**: Each reentrancy call during the callback can burn additional tokens beyond the user's actual balance
 * 3. **Persistent State Changes**: The balanceOf mapping changes persist between transactions, enabling progressive exploitation
 * 
 * **Exploitation Flow:**
 * - Transaction 1: Attacker deploys malicious contract with IBurnCallback
 * - Transaction 2: Attacker calls burn() with legitimate amount
 * - During callback, attacker re-enters burn() multiple times
 * - Each re-entry burns more tokens than originally held
 * - State changes accumulate across the reentrancy calls
 * - Subsequent transactions can continue the attack with updated balances
 * 
 * **Multi-Transaction Requirement:**
 * - Requires separate deployment transaction for attack contract
 * - Each burn call can trigger multiple nested calls via reentrancy
 * - State changes from previous calls enable deeper exploitation
 * - Cannot be exploited atomically - requires external contract interaction
 * 
 * The vulnerability is realistic as burn notifications are common in DeFi protocols, making this a natural integration point that developers might add without considering reentrancy implications.
 */
pragma solidity ^0.4.11;

contract SzeToken {

    string public name = "Szechuan Sauce Coin";      //  token name
    string public symbol = "SZE";           //  token symbol
    uint256 public decimals = 6;            //  token digit

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

    // Constructor syntax updated for Solidity >=0.4.22 compatibility
    function SzeToken(address _addressFounder) public {
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

    // Define the IBurnCallback interface outside of contract scope for Solidity 0.4.x
    /* Interface removed from within the contract, see below for declaration */

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Burn notification callback to external contract
        // This allows protocols to react to token burns
        if (msg.sender.callcode.length > 0) { // fix: code.length is not supported, using extcodesize
            IBurnCallback(msg.sender).onTokenBurn(_value);
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Move the interface definition outside of the contract scope for Solidity 0.4.x
contract IBurnCallback {
    function onTokenBurn(uint256 _value) public;
}
