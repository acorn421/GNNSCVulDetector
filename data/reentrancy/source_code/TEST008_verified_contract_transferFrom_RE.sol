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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack by adding an external call to the recipient address before updating the contract state. The attack exploits the unique 'touched' mechanism and requires multiple transactions to execute:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * 1. **Setup Phase (Transaction 1)**: Attacker approves a malicious contract to spend tokens from their account using approve()
 * 2. **Trigger Phase (Transaction 2)**: Attacker calls transferFrom() with malicious contract as _to address
 * 3. **Reentrancy Phase (Same Transaction 2)**: The malicious contract's onTokenReceived() function re-enters transferFrom() multiple times before state updates occur
 * 4. **Exploitation**: Each reentrant call sees the same unmodified state (balances, allowances, touched status), allowing multiple drains
 * 
 * **Key Vulnerability Mechanics:**
 * 
 * - **Stateful Dependency**: The 'touched' mechanism creates persistent state that can be exploited across calls
 * - **Multi-Transaction Requirement**: Requires separate approve() transaction followed by transferFrom() attack
 * - **External Call Timing**: The callback occurs after balance checks but before state updates (CEI violation)
 * - **Accumulated State Exploitation**: Each reentrant call can drain more funds as the state hasn't been updated yet
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **Allowance Setup**: Must first approve() the attacker contract in a separate transaction
 * 2. **State Accumulation**: The 'touched' mechanism must be triggered and its state must persist for exploitation
 * 3. **Progressive Drainage**: Multiple reentrant calls within the second transaction progressively drain funds
 * 4. **Realistic Attack Pattern**: Mimics real-world attacks where setup and exploitation occur in separate transactions
 * 
 * This creates a realistic vulnerability that requires careful orchestration across multiple transactions, making it harder to detect and more representative of actual production vulnerabilities.
 */
pragma solidity ^0.4.24;

/*
Wo Men Yi Qi Lai Nian Fo:
... (omitted for brevity) ...
*/

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
}

contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract TEST008 is Ownable{
    
    using SafeMath for uint256;
    
    string public constant name       = "TEST008";
    string public constant symbol     = "测试八";
    uint32 public constant decimals   = 18;
    uint256 public totalSupply        = 999999 ether;
    uint256 public currentTotalSupply = 0;
    uint256 startBalance              = 999 ether;
    
    mapping(address => bool) touched;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        if( !touched[msg.sender] && currentTotalSupply < totalSupply ){
            balances[msg.sender] = balances[msg.sender].add( startBalance );
            touched[msg.sender] = true;
            currentTotalSupply = currentTotalSupply.add( startBalance );
        }
        
        require(_value <= balances[msg.sender]);
        
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
    
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
  

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        
        require(_value <= allowed[_from][msg.sender]);
        
        if( !touched[_from] && currentTotalSupply < totalSupply ){
            touched[_from] = true;
            balances[_from] = balances[_from].add( startBalance );
            currentTotalSupply = currentTotalSupply.add( startBalance );
        }
        
        require(_value <= balances[_from]);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state updates - vulnerable to reentrancy
        if (isContract(_to)) {
            // In Solidity 0.4.x, .call is allowed
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of success for compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
     }

    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function getBalance(address _a) internal view returns (uint256) {
        if (!touched[_a] && currentTotalSupply < totalSupply) {
            return balances[_a].add(startBalance);
        } else {
            return balances[_a];
        }
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return getBalance( _owner );
    }
    
    // Helper for old-style contract detection
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
