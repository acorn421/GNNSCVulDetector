/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenLockPeriod
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where token transfers can be locked/unlocked based on block timestamps. The vulnerability is stateful and multi-transaction because: 1) The owner must first call setTokenLockPeriod() or enableTokenLock() to set lockStartTime, 2) The lock state persists across transactions, 3) Users must wait for the timestamp condition to be met before calling disableTokenLock(), 4) The vulnerability allows miners to manipulate block timestamps to either extend or reduce lock periods, potentially allowing premature unlocking or extending locks beyond intended duration. The isTokenLocked() function relies on 'now' (block.timestamp) which can be manipulated by miners within certain bounds.
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
    ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ ᠴᠠᠭᠯᠠᠰᠢ ᠦᠭᠡᠢ ᠭᠡᠷᠡᠯᠲᠦ.
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
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Lock period management for token transfers
    uint256 public lockPeriod = 1 hours;
    uint256 public lockStartTime;
    bool public lockActive = false;
    
    function setTokenLockPeriod(uint256 _lockPeriod) public onlyOwner {
        lockPeriod = _lockPeriod;
        lockStartTime = now;
        lockActive = true;
    }
    
    function enableTokenLock() public onlyOwner {
        lockStartTime = now;
        lockActive = true;
    }
    
    function disableTokenLock() public onlyOwner {
        require(lockActive);
        require(now >= lockStartTime + lockPeriod);
        lockActive = false;
    }
    
    function isTokenLocked() public view returns (bool) {
        if (!lockActive) return false;
        return now < lockStartTime + lockPeriod;
    }
    
    function transferWithLockCheck(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        require(!isTokenLocked() || msg.sender == owner);

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
    // === END FALLBACK INJECTION ===

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
    

    function getBalance(address _a) internal constant returns(uint256)
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