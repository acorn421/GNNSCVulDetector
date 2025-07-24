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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. This creates a reentrancy vector where:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the recipient address (`_to.code.length > 0`)
 * 2. Inserted an external call using `_to.call()` to notify the recipient contract about the incoming transfer
 * 3. The external call occurs AFTER the allowance/balance validation but BEFORE the state updates
 * 4. The call invokes `onTokenReceived(address,address,uint256)` callback on the recipient contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and gets approved allowance from victim
 * 2. **First Call (Transaction 2)**: Legitimate user calls transferFrom() to transfer tokens to attacker's contract
 * 3. **Reentrancy Attack (During Transaction 2)**: The external call triggers attacker's `onTokenReceived` callback
 * 4. **Nested Call (Still Transaction 2)**: Inside the callback, attacker calls transferFrom() again with the same allowance (since allowance hasn't been decremented yet)
 * 5. **State Corruption**: The nested call passes validation checks because state hasn't been updated, allowing double-spending
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability requires initial approval setup (separate transaction)
 * - The attacker must have a deployed contract to receive the callback (deployment transaction)
 * - The exploit depends on the specific timing of state updates vs external calls
 * - Multiple nested calls can be made before the first state update completes, creating cascading effects
 * 
 * **Realistic Attack Vector:**
 * This mirrors real-world ERC20 reentrancy attacks where recipient contracts implement token reception callbacks, commonly seen in DeFi protocols and token standards like ERC777.
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

contract FederalGrid_20210416_i is Ownable {

    string public constant name = " FederalGrid_20210416_i ";
    string public constant symbol = " FEDGRI ";
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
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call before state updates - creates reentrancy opportunity
            if (isContract(_to)) {
                // Notify recipient contract about incoming transfer
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
                // Continue regardless of callback success to maintain functionality
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

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
