/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue. The vulnerability requires: 1) Owner calling initializeReward() to set up pending rewards, 2) User waiting for the reward period, 3) User calling claimTimedReward() where miners can manipulate the timestamp within a ~15 second window to allow premature claims or deny legitimate claims. The state persists between transactions through lastRewardClaim and pendingRewards mappings, making it a stateful vulnerability that requires multiple function calls to exploit.
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

  function Ownable() public {
    owner = msg.sender ;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables must be declared outside the constructor in Solidity 0.4.18
    uint256 public rewardClaimPeriod = 86400; // 24 hours in seconds
    mapping(address => uint256) public lastRewardClaim;
    mapping(address => uint256) public pendingRewards;
    uint256 public rewardRate = 1000 ether; // Base reward amount
    // === END VARIABLE DECLARATIONS ===
    
    function YunJiaMiToken() public {
        balances[msg.sender] = startBalance * 6000000;
        currentTotalSupply = balances[msg.sender];
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    function setRewardParameters(uint256 _period, uint256 _rate) public onlyOwner {
        rewardClaimPeriod = _period;
        rewardRate = _rate;
    }
    
    function initializeReward(address _user) public onlyOwner {
        require(_user != address(0));
        if (pendingRewards[_user] == 0) {
            pendingRewards[_user] = rewardRate;
            lastRewardClaim[_user] = now;
        }
    }
    
    function claimTimedReward() public returns (bool) {
        require(pendingRewards[msg.sender] > 0, "No pending rewards");
        require(now >= lastRewardClaim[msg.sender] + rewardClaimPeriod, "Reward period not elapsed");
        
        uint256 reward = pendingRewards[msg.sender];
        
        // Vulnerability: Using 'now' (block.timestamp) for critical timing
        // Miners can manipulate timestamp within ~15 second window
        lastRewardClaim[msg.sender] = now;
        
        // Multi-transaction vulnerability: pendingRewards is not reset immediately
        // allowing potential manipulation through timestamp manipulation
        if (currentTotalSupply.add(reward) <= totalSupply) {
            balances[msg.sender] = balances[msg.sender].add(reward);
            currentTotalSupply = currentTotalSupply.add(reward);
            
            // Only reset rewards after successful claim
            pendingRewards[msg.sender] = 0;
            
            Transfer(address(0), msg.sender, reward);
            return true;
        }
        
        return false;
    }
    // === END FALLBACK INJECTION ===

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
    
        Transfer(msg.sender, _to, _value);
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
        Transfer(_from, _to, _value);
        return true;
    }


    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }


    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
     }


    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
        Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }


    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
          allowed[msg.sender][_spender] = 0;
        } else {
          allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
        }
        Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
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
