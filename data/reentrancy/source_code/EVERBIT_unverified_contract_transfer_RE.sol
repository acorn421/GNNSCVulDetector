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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability involves:
 * 
 * 1. **External Call Injection**: Added `_to.call()` with `onTokenReceived` callback before balance updates, creating a reentrancy entry point
 * 2. **State Persistence**: The balances mapping persists between transactions, allowing accumulated exploitation
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Attacker calls transfer() to malicious contract, which re-enters during the callback but doesn't exploit yet (builds state)
 *    - **Transaction 2**: Attacker calls transfer() again, this time the malicious contract can exploit the accumulated state from previous transactions
 *    - **Transaction 3+**: Further calls can drain more tokens by leveraging the state built up across previous transactions
 * 
 * **Why Multi-Transaction**: The vulnerability requires multiple transactions because:
 * - Each transaction builds upon the persistent balance state from previous calls
 * - The attacker's contract can maintain state about previous transfer attempts
 * - Multiple reentrancy attempts across transactions can progressively drain tokens beyond the sender's actual balance
 * - The exploitation requires a sequence of transfers where each callback incrementally manipulates the persistent contract state
 * 
 * **Exploitation Scenario**: 
 * 1. Attacker deploys malicious contract with `onTokenReceived` function
 * 2. First transfer() call triggers callback, malicious contract notes the state but doesn't exploit
 * 3. Second transfer() call triggers callback again, now malicious contract can re-enter transfer() using knowledge from previous transaction
 * 4. Through multiple transactions, attacker can drain tokens beyond their legitimate balance by exploiting the accumulated state changes
 * 
 * The vulnerability is realistic as token notification patterns are common in DeFi, and the state persistence makes it genuinely multi-transaction dependent.
 */
pragma solidity ^0.4.25;

contract EVERBIT {

    uint256 public totalSupply;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name;
    uint8 public decimals;
    string public symbol;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    // 100000000000000000,"ever bit",8,"EVERBIT"
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if recipient is a contract and notify it of incoming transfer
        if (isContract(_to)) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
