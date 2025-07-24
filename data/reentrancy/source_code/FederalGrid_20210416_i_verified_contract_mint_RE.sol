/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit: 1) Initial mint() call triggers external callback, 2) Malicious contract can call mint() again during callback before first transaction's state updates are committed, 3) This creates inconsistent state across multiple transactions where totalSupply and balances can be manipulated. The vulnerability is stateful because it depends on the contract's code presence check and accumulated state changes across transaction boundaries. A single transaction cannot exploit this as it requires the external callback to trigger additional mint calls that compound the state inconsistencies.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}

// Declare interface for callback
interface IMintCallback {
    function onTokensMinted(address minter, uint amount);
}

contract FederalGrid_20210416_i is Ownable {
    string public constant name = " FederalGrid_20210416_i        ";
    string public constant symbol = "FEDGRI        ";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract (common pattern in modern tokens)
        if (isContract(_to)) {
            // External call before state updates - VULNERABILITY INJECTION POINT
            IMintCallback(_to).onTokensMinted(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }

    function isContract(address _addr) internal returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function balanceOf(address _owner) constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) returns (bool success) {
        if (balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) returns (bool success) {
        if (
            allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value &&
            balances[_to] + _value >= balances[_to]
        ) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }

    function approve(address _spender, uint _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
