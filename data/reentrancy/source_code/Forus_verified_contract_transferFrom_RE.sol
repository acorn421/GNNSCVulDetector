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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic violation of the Checks-Effects-Interactions pattern where:
 * 
 * 1. **Multi-Transaction Setup Required**: An attacker must first deploy a malicious contract and set up allowances across multiple transactions
 * 2. **State Accumulation**: The vulnerability exploits the gap between balance/allowance checks and their updates, requiring the attacker to accumulate allowances over multiple transactions
 * 3. **Reentrancy Window**: The external call to `_to.call()` before state updates allows the malicious contract to re-enter transferFrom while the original state is still unchanged
 * 
 * **Exploitation Sequence** (Multi-Transaction):
 * - **Transaction 1**: Attacker deploys malicious contract and gets approval for large allowance
 * - **Transaction 2**: Attacker calls transferFrom, triggering the external call to their malicious contract
 * - **During Transaction 2**: The malicious contract's `onTokensReceived` function re-enters transferFrom multiple times before the original state updates complete
 * - **Result**: Multiple transfers occur using the same allowance balance, draining more tokens than authorized
 * 
 * **Why Multi-Transaction**: The vulnerability requires prior allowance setup and a malicious contract deployment, making it impossible to exploit in a single transaction. The attacker must accumulate sufficient allowances across multiple transactions to make the reentrancy profitable.
 */
pragma solidity ^0.4.13;

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
contract Forus{
     string public constant symbol = "FRS";
     string public constant name = "Forus";
     uint8 public constant decimals = 12;
     uint256 _totalSupply = 220000000000000000000;
     event Transfer(address indexed from, address indexed to, uint256 value);
     event Approval(address indexed _owner, address indexed spender, uint256 value);
   
       address public owner;
  
     mapping(address => uint256) balances;
  
     mapping(address => mapping (address => uint256)) allowed;
     
  
     constructor() public {
         owner = msg.sender;
         balances[owner] = 220000000000000000000;
     }
     
     modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
     
     function totalSupply() constant returns (uint256) {
         return _totalSupply;
     }

     function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
     }
 
     function transfer(address _to, uint256 _amount) returns (bool success) {
         if (balances[msg.sender] >= _amount 
            && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[msg.sender] -= _amount;
             balances[_to] += _amount;
             emit Transfer(msg.sender, _to, _amount);
            return true;
         } else {
             return false;
         }
     }
     
     
     function transferFrom(
         address _from,
         address _to,
         uint256 _amount
     ) returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             // Transfer recipient notification - external call before state updates
             if (isContract(_to)) {
                 bool notificationResult = _to.call(bytes4(keccak256("onTokensReceived(address,address,uint256)")), _from, _to, _amount);
             }
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             emit Transfer(_from, _to, _amount);
             return true;
         } else {
            return false;
         }
     }

     function approve(address _spender, uint256 _amount) returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
         return true;
     }
  
     function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
         return allowed[_owner][_spender];
    }

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
