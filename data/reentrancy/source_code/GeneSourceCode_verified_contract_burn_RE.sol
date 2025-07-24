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
 * The vulnerability is introduced by adding an external call to a user-controlled contract (msg.sender) before updating the balance state. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **State Persistence**: The balanceOf mapping persists between transactions, allowing an attacker to exploit the vulnerability across multiple calls
 * 2. **Multi-Transaction Exploitation**: An attacker can deploy a malicious contract that implements the BurnNotifier interface
 * 3. **Reentrancy Window**: The external call occurs before the balance is decremented, allowing the attacker to re-enter the burn function with the same balance
 * 4. **Stateful Nature**: The vulnerability requires the attacker to have tokens in their balance initially, and each successful reentrancy burns more tokens than the attacker actually owns
 * 
 * The attack sequence requires multiple transactions:
 * - Transaction 1: Deploy malicious contract with BurnNotifier interface
 * - Transaction 2: Call burn() which triggers the callback, allowing reentrancy
 * - The callback can call burn() again before the original balance is decremented
 * - Multiple reentrant calls can burn tokens the attacker doesn't actually possess
 * 
 * This creates a stateful vulnerability where the attacker's balance state from previous transactions enables the exploit in subsequent transactions.
 */
pragma solidity ^0.4.11;

contract GeneSourceCode {

    string public name = "Gene Source Code Chain";      //  the GSC Chain token name
    string public symbol = "Gene";           //  the GSC Chain token symbol
    uint256 public decimals = 18;            //  the GSC Chain token digits

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2000000000000000000000000000;
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

    function GeneSourceCode(address _addressFounder) public {
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
        // Notify external systems about the burn event
        if (balanceOf[msg.sender] > 0) {
            address burnCallback = msg.sender;
            if (isContract(burnCallback)) {
                // External call to onBurnNotification (REENTRANCY)
                BurnNotifier(burnCallback).onBurnNotification(msg.sender, _value);
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    function isContract(address _addr) private view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Interface for the burn notifier (for external reentrancy call)
contract BurnNotifier {
    function onBurnNotification(address _from, uint256 _value) public;
}
