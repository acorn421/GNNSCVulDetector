/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external call to the recipient address (_to) before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient using `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))`
 * 2. Placed the external call after initial checks but before critical state updates (balance and allowance modifications)
 * 3. The call happens before allowance deduction, creating a window for reentrancy
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker sets up allowance through approve() function
 * 2. **Transaction 2**: Attacker calls transferFrom() with malicious contract as recipient
 * 3. **During Transaction 2**: The malicious contract receives the onTokenReceived callback and can re-enter transferFrom()
 * 4. **Reentrancy Window**: The callback happens after allowance verification but before allowance deduction
 * 5. **Exploitation**: The attacker can repeatedly call transferFrom() using the same allowance amount before it gets decremented
 * 
 * **Why Multi-Transaction Required:**
 * - Transaction 1 is needed to establish the allowance state through approve()
 * - Transaction 2 triggers the initial transferFrom() call
 * - The vulnerability exploits the persistent allowance state that was set in Transaction 1
 * - Each reentrant call within Transaction 2 uses the same allowance value since the deduction happens after the external call
 * - The attacker can drain funds beyond their approved allowance by exploiting the state inconsistency
 * 
 * **State Persistence Factor:**
 * - The allowance state persists between transactions and is crucial for the exploit
 * - Balance states accumulate changes across multiple reentrant calls
 * - The vulnerability depends on the gap between allowance verification and allowance deduction
 */
pragma solidity ^0.4.26;
contract HPB {
    address public owner;
    mapping (address => uint) public balances;
    address[] public users;
    uint256 public total=0;
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => mapping (address => uint256)) public allowed;
    uint256 public totalSupply=10000000000000000;
    string public name="Health Preservation Treasure";
    uint8 public decimals=8;
    string public symbol="HPT";
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public{
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    function userCount() public view returns (uint256) {
        return users.length;
    }

    function getTotal() public view returns (uint256) {
        return total;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function contractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient before state updates - creates reentrancy window
        if (isContract(_to)) {
            // Change variable name from 'success' to 'callSuccess' to avoid shadowing
            (bool callSuccess, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Allowance update happens after external call and balance changes
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if _addr is a contract (Solidity ^0.4.x compatible)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function() public payable {
        if (msg.value > 0 ) {
            total += msg.value;
            bool isfind=false;
            for(uint i=0;i<users.length;i++)
            {
                if(msg.sender==users[i])
                {
                    isfind=true;
                    break;
                }
            }
            if(!isfind){users.push(msg.sender);}
        }
    }
}
