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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an ERC-677 style callback mechanism that allows the recipient contract to execute arbitrary code after balance updates but before the Transfer event. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenTransfer` signature after balance/allowance updates
 * 2. Placed the external call before the Transfer event emission
 * 3. Used low-level `call()` instead of interface to avoid compilation dependencies
 * 4. Added backward compatibility by continuing execution regardless of callback success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction:** Attacker deploys a malicious contract and gets approval for token transfers
 * 2. **Exploitation Transaction:** Attacker calls `transferFrom()` which triggers the callback to their malicious contract
 * 3. **Reentrancy Attack:** The malicious contract's `onTokenTransfer` function calls back to `transferFrom()` or other functions before the initial transaction completes
 * 4. **State Inconsistency:** The reentrant call exploits the fact that balances are updated but the Transfer event hasn't been emitted yet, creating opportunities for double-spending or allowance manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior setup of allowances through separate `approve()` calls
 * - The malicious contract must be deployed and funded in separate transactions
 * - The exploit depends on accumulated state (approved allowances) from previous transactions
 * - The reentrancy callback creates a window where contract state is inconsistent across multiple nested calls, requiring the attacker to have pre-positioned resources and permissions
 * 
 * This creates a realistic vulnerability pattern seen in tokens implementing callback mechanisms while maintaining the original function's intended behavior.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract TeslaCdsTok20221205I is Ownable {
    
    string public constant name = "TeslaCdsTok20221205I";
    
    string public constant symbol = "TESLAII";
    
    uint32 public constant decimals = 8;
    
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
            emit Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // ERC-677 style callback for enhanced token functionality
            if (isContract(_to)) {
                // External call before Transfer event - creates reentrancy opportunity
                (bool callSuccess,) = _to.call(
                    abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value)
                );
                // Continue execution regardless of callback success for backward compatibility
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
}