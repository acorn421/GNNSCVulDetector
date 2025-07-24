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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability exploits the interaction between the `touched` mapping state and the balance initialization logic across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls `transfer()` to a malicious contract that implements `onTokenReceived()`. During the external call, the malicious contract re-enters `transfer()` but the `touched[msg.sender]` is already set to true, so no additional balance is added. The attacker's balance is reduced but the recipient's balance is increased.
 * 
 * 2. **Transaction 2 (Exploitation)**: The attacker creates a new account (not yet touched) and calls `transfer()` again. The malicious contract's `onTokenReceived()` function now re-enters with this new account. Since the new account hasn't been touched, it gets the `startBalance` added. However, the external call happens before the final balance updates, allowing the attacker to manipulate the state during the callback.
 * 
 * 3. **Accumulated State Vulnerability**: Across multiple transactions, the attacker can exploit the timing of when `touched` is set versus when balances are updated, especially when combined with the external call occurring before state finalization.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires building up state across multiple calls because the `touched` mapping prevents immediate re-exploitation
 * - The attacker needs to accumulate state changes across different accounts or timing windows
 * - The external call creates a window where state is partially updated, but full exploitation requires multiple transactions to build up the necessary conditions
 * - The interaction between `currentTotalSupply` limits and `touched` status creates a stateful vulnerability that can only be fully exploited through a sequence of carefully timed transactions
 */
pragma solidity ^0.4.24;

    /*
    Wo Men Yi Qi Lai Nian Fo:
    अमिताभ अमिताभ अमिताभ अमिताभ अमिताभ अमिताभ अमिताभ अमिताभ अमिताभ अमिताभ.
    འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད། འོད་དཔག་མེད།.
    아미타불 아미타불 아미타불 아미타불 아미타불 아미타불 아미타불 아미타불 아미타불 아미타불.
    阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛 阿弥陀佛.
    阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛 阿彌陀佛.
    Amitabha Amitabha Amitabha Amitabha Amitabha Amitabha Amitabha Amitabha Amitabha Amitabha.
    พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ พระอมิตาภพุทธะ.
    Adiđàphật Adiđàphật Adiđàphật Adiđàphật Adiđàphật Adiđàphật Adiđàphật Adiđàphật Adiđàphật Adiđàphật.
    ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ.
    Jiang Wo Suo Xiu De Yi Qie Gong De,Hui Xiang Gei Fa Jie Yi Qie Zhong Sheng.
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient with external call before state updates
        if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
            // External call succeeded, continue with transfer
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
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