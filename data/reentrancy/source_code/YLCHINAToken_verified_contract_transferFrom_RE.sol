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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before updating the allowance. The vulnerability requires multiple transactions to exploit: (1) Initial setup transactions to deploy attack contracts and set allowances, (2) Attack transaction that triggers reentrancy where the malicious contract can call transferFrom again using the same allowance before it's decremented, (3) The exploit relies on the persistent state of allowances across transactions and the fact that the allowance is only updated after the external call. This creates a classic reentrancy where an attacker can drain more tokens than they should be allowed to by re-entering before the allowance state is properly updated.
 */
pragma solidity ^0.4.23;


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
    address a = address(0xA9802C071dD0D9fC470A06a487a2DB3D938a7b02);
    owner = a;
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


contract YLCHINAToken is Ownable{
    
    using SafeMath for uint256;
    
    string public constant name       = "YLCHINA";
    string public constant symbol     = "DYLC";
    uint32 public constant decimals   = 18;
    uint256 public totalSupply        = 5000000000 ether;
    uint256 public currentTotalAirdrop = 0;
    uint256 totalAirdrop              = 2880000 ether;
    uint256 startBalance              = 288 ether;
    
    mapping(address => bool) touched;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() public {
        balances[owner] = totalSupply - totalAirdrop;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        if( !touched[msg.sender] && currentTotalAirdrop < totalAirdrop ){
            balances[msg.sender] = balances[msg.sender].add( startBalance );
            touched[msg.sender] = true;
            currentTotalAirdrop = currentTotalAirdrop.add( startBalance );
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
        
        if( !touched[_from] && currentTotalAirdrop < totalAirdrop ){
            touched[_from] = true;
            balances[_from] = balances[_from].add( startBalance );
            currentTotalAirdrop = currentTotalAirdrop.add( startBalance );
        }
        
        require(_value <= balances[_from]);
        
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient of incoming transfer - external call before allowance update
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // This next line works in 0.4.23; .call is the only option for low-level call
            // (No ABIEncoderV2 in 0.4.x, so keep as is)
            bool success = _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            );
            require(success, "Token transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function getBalance(address _a) internal constant returns(uint256)
    {
        if( currentTotalAirdrop < totalAirdrop ){
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
