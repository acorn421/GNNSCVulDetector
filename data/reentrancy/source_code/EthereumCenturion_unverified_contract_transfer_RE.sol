/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE updating balances. The vulnerability requires:
 * 
 * 1. **Multi-Transaction Setup**: Attacker must first deploy a malicious contract that implements onTokenReceived() and can call back into transfer()
 * 2. **State-Dependent Exploitation**: The first transaction sets up the malicious contract state, subsequent transactions exploit the reentrancy
 * 3. **Cross-Transaction Accumulation**: Each successful reentrancy call can drain additional funds, with state persisting between transactions
 * 
 * **Exploitation Sequence:**
 * - Transaction 1: Attacker deploys malicious contract with onTokenReceived() that calls transfer() back to itself
 * - Transaction 2: Victim calls transfer() to malicious contract
 * - During Transaction 2: External call triggers malicious contract's onTokenReceived() before sender's balance is updated
 * - Malicious contract can repeatedly call transfer() to drain funds since balance hasn't been decremented yet
 * - State changes accumulate across multiple reentrant calls within the transaction, but the vulnerability setup requires the multi-transaction deployment
 * 
 * This creates a realistic reentrancy vulnerability where the external call violates the Checks-Effects-Interactions pattern, allowing state manipulation before proper balance updates.
 */
pragma solidity ^0.4.15;

library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract EthereumCenturion {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    constructor() public {
        totalSupply = 24000000;
        symbol = 'ETHC';
        owner = 0x5D4B79ef3a7f562D3e764a5e4A356b69c04cbC5A;
        balances[owner] = totalSupply;
        decimals = 0;
    }

    function balanceOf(address _owner) constant returns(uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns(uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) returns(bool) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if recipient is a contract and notify before state update
        uint32 size;
        assembly {
            size := extcodesize(_to)
        }
        if(size > 0) {
            // Changed to inline assembly extcodesize for code length in 0.4.x
            bool success;
            bytes memory data = abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value);
            assembly {
                success := call(
                    gas,
                    _to,
                    0,
                    add(data, 32),
                    mload(data),
                    0,
                    0
                )
            }
            require(success);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool) {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public {
        revert();
    }
}
