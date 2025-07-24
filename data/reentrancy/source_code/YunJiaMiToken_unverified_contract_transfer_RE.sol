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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts about token transfers. The vulnerability exploits the decreasing startBalance state variable across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))`
 * 2. Placed the external call after balance updates but before the Transfer event and startBalance modification
 * 3. Added a check for contract recipients using `_to.code.length > 0` to make it realistic
 * 4. Continued execution regardless of call success to maintain backward compatibility
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker transfers tokens to a malicious contract, triggering the external call
 * 2. **Malicious Contract**: In the `onTokenReceived` callback, re-enters the transfer function multiple times
 * 3. **Key Exploit**: The startBalance decreases with each completed transfer (`startBalance = startBalance.div(1000000).mul(999999)`)
 * 4. **Transaction 2+**: Subsequent legitimate transfers from new users will receive smaller bonuses due to the manipulated startBalance
 * 5. **State Accumulation**: The attacker can drain the bonus system across multiple transactions by repeatedly triggering the reentrancy
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the persistent state change of startBalance decreasing over time
 * - Each reentrancy call in Transaction 1 causes startBalance to decrease
 * - The real exploitation happens in subsequent transactions when legitimate users receive smaller bonuses
 * - The attacker needs to accumulate the effect across multiple calls to significantly impact the token economy
 * - Single transaction exploitation is limited by gas limits and the gradual nature of startBalance reduction
 * 
 * **Realistic Vulnerability Pattern:**
 * This follows a common pattern where tokens implement recipient notification mechanisms for better UX, but fail to implement proper reentrancy protection. The vulnerability is subtle because it doesn't directly steal tokens but manipulates the economic incentives of the contract over time.
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
    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about the transfer - potential reentrancy point
        if (isContract(_to)) {
            (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of success to maintain backward compatibility
        }
    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

}
