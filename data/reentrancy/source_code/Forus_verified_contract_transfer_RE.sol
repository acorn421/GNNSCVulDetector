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
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding external call to recipient before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker deploys malicious contract implementing ITokenReceiver
 * 2. **Transaction 2**: Someone transfers tokens to attacker's contract, triggering onTokenReceived callback
 * 3. **During callback**: Attacker's contract re-enters transfer function before balances are updated
 * 4. **Multi-transaction exploitation**: Each reentrant call sees stale balance state, allowing multiple transfers
 * 
 * **Why Multi-Transaction:**
 * - Setup transaction needed to deploy malicious receiver contract
 * - Trigger transaction initiates the vulnerable transfer
 * - Reentrancy occurs during external call, but exploits accumulated state changes
 * - Each nested call can manipulate balances based on previous transaction states
 * 
 * **State Persistence Factor:**
 * - balances mapping maintains state between transactions
 * - External call happens before balance updates, creating window for reentrancy
 * - Attacker can drain sender's balance by calling transfer multiple times before state is finalized
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

// Interface for recipient contract to handle receiving tokens
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 amount) external;
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
     
     function totalSupply() public constant returns (uint256) {
         return _totalSupply;
     }

     function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
     }
 
     function transfer(address _to, uint256 _amount) public returns (bool success) {
         if (balances[msg.sender] >= _amount 
            && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             
             // Notify recipient before updating balances (external call)
             if (isContract(_to)) {
                 ITokenReceiver(_to).onTokenReceived(msg.sender, _amount);
             }
             
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
             balances[msg.sender] -= _amount;
             balances[_to] += _amount;
             Transfer(msg.sender, _to, _amount);
            return true;
         } else {
             return false;
         }
     }
     // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
     
     // Helper function to check if address is contract
     function isContract(address account) internal view returns (bool) {
         uint256 size;
         assembly { size := extcodesize(account) }
         return size > 0;
     }
     // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
     
     
     function transferFrom(
         address _from,
         address _to,
         uint256 _amount
     ) public returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             Transfer(_from, _to, _amount);
             return true;
         } else {
            return false;
         }
     }
 
     function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
         return true;
     }
  
     function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
         return allowed[_owner][_spender];
    }
}
