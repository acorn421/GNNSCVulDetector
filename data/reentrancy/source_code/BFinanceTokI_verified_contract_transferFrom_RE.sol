/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after allowance deduction but before balance updates. The vulnerability allows for multi-transaction exploitation where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom, triggering the external call. During this call, the attacker can observe that allowance is already decremented but balances haven't been updated yet.
 * 
 * 2. **Transaction 2**: Attacker exploits the intermediate state by calling transferFrom again in a separate transaction. Since the allowance was partially consumed in Transaction 1, but the balance updates hadn't completed, the attacker can potentially manipulate the state across multiple transactions.
 * 
 * 3. **State Accumulation**: The vulnerability requires multiple transactions because the allowance restoration mechanism creates a window where state is inconsistent across transactions, enabling exploitation through accumulated state changes.
 * 
 * The external call to onTokenReceived() appears legitimate (similar to ERC777 token callbacks) but creates a reentrancy point where the contract state is in an intermediate condition, making it exploitable across multiple transactions rather than in a single atomic transaction.
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

contract BFinanceTokI is Ownable {

    string public constant name = "\tBFinanceTokI\t\t";
    string public constant symbol = "\tBFTI\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) returns (bool success) {
        if(allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call to notify recipient (potential reentrancy point)
            // Solidity <0.5.0 has no address.code.length, so instead check extcodesize
            uint256 len;
            address a = _to;
            assembly { len := extcodesize(a) }
            if (len > 0) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
                if(!callSuccess) {
                    // Restore allowance if callback fails, but continue transfer
                    allowed[_from][msg.sender] += _value;
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
