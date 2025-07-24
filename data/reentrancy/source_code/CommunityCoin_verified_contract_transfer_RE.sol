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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before the touched flag is set. This creates a critical window where:
 * 
 * 1. **Transaction 1**: Attacker calls transfer(), receives airdrop tokens, but external call allows reentrancy before touched[msg.sender] is set to true
 * 2. **Transaction 2+**: During the external call, attacker can re-enter transfer() or other functions while the airdrop state is inconsistent (balance updated but touched flag not yet set)
 * 
 * The vulnerability is multi-transaction because:
 * - The attacker needs to deploy a malicious contract that implements onTokenReceived()
 * - First transaction triggers the airdrop and external call
 * - The malicious contract can then make additional calls during the callback, exploiting the inconsistent state
 * - Multiple rounds of exploitation can occur as the touched flag isn't set until after the external call
 * 
 * This creates a race condition where the attacker can:
 * - Receive multiple airdrops by re-entering before touched flag is set
 * - Transfer tokens while balance calculations are inconsistent
 * - Exploit the state across multiple function calls during the reentrancy window
 * 
 * The vulnerability preserves the original function's behavior while introducing a realistic security flaw that requires careful transaction orchestration to exploit.
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


contract CommunityCoin is Ownable{
    
    using SafeMath for uint256;
    
    string public constant name       = "Community Coin";
    string public constant symbol     = "SQ";
    uint32 public constant decimals   = 4;
    uint256 public totalSupply        = 2100000000 * (10 ** uint256(decimals));
    uint256 public currentTotalSupply = 0;
    uint256 startBalance              = 2000 * (10 ** uint256(decimals));
    
    mapping(address => bool) touched;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;
    
        function  CommunityCoin()  public {
        balances[msg.sender] = startBalance * 1000000;
        currentTotalSupply = balances[msg.sender];
    }
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        if( !touched[msg.sender] && currentTotalSupply < totalSupply ){
            balances[msg.sender] = balances[msg.sender].add( startBalance );
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            currentTotalSupply = currentTotalSupply.add( startBalance );
            
            // External call to recipient before setting touched flag - enables reentrancy
            if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
                // Call succeeded, continue execution
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            touched[msg.sender] = true;
        }
        
        require(_value <= balances[msg.sender]);
        
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
    
        Transfer(msg.sender, _to, _value);
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