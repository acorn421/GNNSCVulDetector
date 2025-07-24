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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived` function. This contract is designed to re-enter the transfer function when called.
 * 
 * 2. **Transaction 2 (Initial Transfer)**: Attacker calls `transfer()` to send tokens to their malicious contract. During this transaction:
 *    - Balances are updated first (sender decreases, recipient increases)
 *    - The external call to `_to.call()` is made to notify the recipient
 *    - The malicious contract's `onTokenReceived` function is triggered
 *    - During this callback, the malicious contract can call `transfer()` again, seeing the updated balances from the first call
 * 
 * 3. **Transaction 3+ (Exploitation)**: The malicious contract can leverage the persistent state changes from previous transactions to manipulate balances across multiple calls, potentially draining more tokens than should be possible.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability accumulates state changes across multiple transactions
 * - Each reentrancy call builds upon the balance state modified by previous calls
 * - The attacker needs to establish the malicious contract first, then trigger the vulnerable flow
 * - The exploit becomes effective only after the state has been modified by earlier transactions
 * 
 * **Key Vulnerability Elements:**
 * - External call made after state updates but before completion
 * - State changes persist between transactions and enable further exploitation
 * - The callback mechanism allows the attacker to re-enter with modified state
 * - Failure handling creates additional attack vectors by reverting state changes
 */
pragma solidity ^0.4.13;

contract Ownable {
    address public owner;
    function Ownable() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract NAUTokenCoin is Ownable {
    string public constant name = "eNAU";
    string public constant symbol = "ENAU";
    uint32 public constant decimals = 4;
    uint public constant INITIAL_SUPPLY = 12850000000000;
    uint public totalSupply = 0;
    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;
    function NAUTokenCoin () public {
        totalSupply = INITIAL_SUPPLY;
        balances[msg.sender] = INITIAL_SUPPLY;
    }
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }
    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[msg.sender] + _value >= balances[msg.sender]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient contract about the transfer
            if (isContract(_to)) {
                // Construct the low-level call
                // Note: call.value(0)(bytes4, args)
                bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256)"));
                bool callSuccess = _to.call(sig, msg.sender, _value);
                if (!callSuccess) {
                    // If notification fails, revert the transfer
                    balances[msg.sender] += _value;
                    balances[_to] -= _value;
                    return false;
                }
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
