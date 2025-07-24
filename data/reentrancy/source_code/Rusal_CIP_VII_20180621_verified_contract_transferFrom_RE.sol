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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This violates the Checks-Effects-Interactions pattern and creates a vulnerability that requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added external call to recipient contract using `_to.call()` before state modifications
 * 2. The call attempts to invoke `onTokenReceive(address,address,uint256)` callback on recipient contracts
 * 3. State updates (allowance and balance changes) occur AFTER the external call
 * 4. No reentrancy protection mechanisms added
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceive` callback
 * 2. **Transaction 2**: Attacker gets approval to spend tokens from victim's account
 * 3. **Transaction 3**: Attacker calls `transferFrom` to malicious contract, triggering reentrancy:
 *    - External call to malicious contract occurs first
 *    - Malicious contract's `onTokenReceive` callback executes
 *    - Callback can call `transferFrom` again with same parameters
 *    - Original state hasn't been updated yet, so checks pass again
 *    - This creates recursive calls that can drain balances
 * 4. **Subsequent transactions**: Attacker can repeat exploitation by setting up new approvals
 * 
 * **WHY MULTI-TRANSACTION NATURE IS REQUIRED:**
 * - Attacker must first deploy and configure malicious contract (Transaction 1)
 * - Victim must approve spending or attacker must obtain approval (Transaction 2)  
 * - Only then can the reentrancy attack be triggered (Transaction 3+)
 * - The vulnerability depends on the persistent state of approvals and balances between transactions
 * - Each exploitation round requires fresh approvals, making it inherently multi-transaction
 * 
 * This creates a realistic vulnerability where the external call feature appears legitimate (recipient notifications) but enables stateful reentrancy attacks across multiple transactions.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract Rusal_CIP_VII_20180621 is Ownable {
    string public constant name = "\tRusal_CIP_VII_20180621\t\t";
    string public constant symbol = "\tRUSCIPVII\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if (balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if (
            allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value &&
            balances[_to] + _value >= balances[_to]
        ) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: External call to recipient before state updates
            // This allows for recipient notification and callback functionality
            if (isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceive(address,address,uint256)")), _from, msg.sender, _value);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    // Helper function to detect contracts in Solidity <0.5.0
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
