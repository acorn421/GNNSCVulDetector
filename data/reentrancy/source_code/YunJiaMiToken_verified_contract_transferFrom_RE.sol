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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state changes are finalized. The vulnerability works as follows:
 * 
 * **Changes Made:**
 * 1. Added an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after balance requirements are checked but before state updates
 * 2. Added a check `if (_to.code.length > 0)` to only call contracts (realistic behavior)
 * 3. Used low-level call to avoid reverting the entire transaction if recipient contract fails
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contract and calls `approve()` to give the malicious contract allowance to transfer tokens from victim's account
 * 2. **Transaction 2 (Exploit)**: Malicious contract calls `transferFrom()` with itself as `_to`. During the external call to `onTokenReceived()`, the malicious contract:
 *    - Observes that balances haven't been updated yet but allowance checks passed
 *    - Records the current state and transaction parameters
 *    - Does NOT reenter immediately (to avoid single-transaction reentrancy detection)
 * 3. **Transaction 3 (Second Exploit)**: Based on recorded state, malicious contract calls `transferFrom()` again with carefully crafted parameters, potentially:
 *    - Exploiting the fact that `touched[_from]` status was set in Transaction 2
 *    - Using the accumulated state knowledge to drain more tokens than intended
 *    - Leveraging timing between allowance checks and balance updates
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first gain allowance (Transaction 1)
 * - Then exploit the reentrancy window to gather state information (Transaction 2)  
 * - Finally use that information in a subsequent transaction (Transaction 3)
 * - The `touched` mapping creates persistent state that can be exploited across transactions
 * - Single-transaction reentrancy would be detected by balance inconsistencies, but multi-transaction approach allows for more sophisticated state manipulation
 * 
 * The vulnerability is realistic as many DeFi protocols implement recipient notification callbacks, and the placement before state updates follows a common anti-pattern in smart contract development.
 */
pragma solidity ^0.4.18;

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
    owner = msg.sender ;
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

contract YunJiaMiToken is Ownable{
    
    using SafeMath for uint256;
    
    string public constant name       = "YunJiaMi";
    string public constant symbol     = "YJM";
    uint32 public constant decimals   = 18;
    uint256 public totalSupply        = 800000000000 ether;
    uint256 public currentTotalSupply = 0;
    uint256 startBalance              = 100000 ether;
    
    mapping(address => bool) touched;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;
    
    constructor() public {
        balances[msg.sender] = startBalance * 6000000;
        currentTotalSupply = balances[msg.sender];
    }
    
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
        startBalance = startBalance.div(1000000).mul(999999);
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
        // External call to notify recipient before state changes are finalized
        // This creates a reentrancy window where contract state is inconsistent
        if (isContract(_to)) {
            // We use assembly to maintain low-level call for compatibility with 0.4.18 and gas estimator
            // _to.call(abi.encodeWithSignature...) is not available before 0.5.0; using .call() with constructed signature.
            // The result of the call is ignored as per original intent.
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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


    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
          allowed[msg.sender][_spender] = 0;
        } else {
          allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
     }
    

    function getBalance(address _a) internal view returns(uint256)
    {
        if( currentTotalSupply < totalSupply ){
            if( touched[_a] )
                return balances[_a];
            else
                return balances[_a].add( startBalance );
        } else {
            return balances[_a];
        }
    }
    

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return getBalance( _owner );
    }

}