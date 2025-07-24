/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a recipient notification mechanism using `_to.call()` that occurs BEFORE balance updates, violating the Checks-Effects-Interactions (CEI) pattern.
 * 
 * 2. **Contract Detection**: Added `_to.code.length > 0` check to only call contracts, making the vulnerability more realistic and targeted.
 * 
 * 3. **Callback Interface**: The external call targets `onTokenReceived(address,uint256)` function, a common pattern in token contracts for recipient notification.
 * 
 * 4. **State Update Vulnerability**: Balance modifications (`balances[msg.sender] -= _value` and `balances[_to] += _value`) happen AFTER the external call, creating a window for reentrancy.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - Contract implements reentrancy logic that calls `transfer` again
 * - During the external call, balances haven't been updated yet
 * - The reentrant call can pass the `require(balances[msg.sender] >= _value)` check using the same balance multiple times
 * 
 * **Transaction 2+ (Exploitation):**
 * - Each subsequent transaction builds on the state corruption from previous transactions
 * - The attacker can drain tokens by repeatedly exploiting the inconsistent state
 * - The vulnerability compounds across multiple transactions as the balance state becomes increasingly corrupted
 * 
 * **Why Multi-Transaction Requirement:**
 * 
 * 1. **State Accumulation**: Each reentrancy attempt leaves the contract in a partially updated state that persists between transactions
 * 2. **Persistent State Corruption**: The `balances` mapping retains corrupted values across transaction boundaries
 * 3. **Cumulative Effect**: Multiple exploitation attempts compound the damage, as each transaction can exploit the corrupted state from previous transactions
 * 4. **Sequential Dependency**: Later transactions rely on the state modifications from earlier transactions to be exploitable
 * 
 * **Realistic Integration**: This vulnerability appears as a legitimate "transfer hook" feature common in modern token contracts, making it subtle and realistic while creating a genuine multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.19;

interface ERC20 {
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

/**
 * Aethia CHI Token
 *
 * Chi is the in-game currency used throughout Aethia. This contract governs
 * the ownership and transfer of all Chi within the game.
 */
contract ChiToken is ERC20 {

    string public name = 'Chi';
    string public symbol = 'CHI';
    uint256 _totalSupply = 10000000000;
    uint256 public decimals = 0;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        balances[msg.sender] = _totalSupply;
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public view returns (uint256) {
        return balances[_owner];
    }

    // ===== Vulnerable transfer: reentrancy preserved (from interface, injected vulnerability) =====
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of incoming transfer (external call before state update)
        if (isContract(_to)) {
            bool success = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            require(success, "Transfer notification failed");
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }
    // ===== End vulnerable transfer implementation =====

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balances[_from] >= _value);
        require(allowances[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowances[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowances[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowances[_owner][_spender];
    }

    // Helper function for contract detection, since Solidity 0.4.x doesn't support _to.code.length
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
