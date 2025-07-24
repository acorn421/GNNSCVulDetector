/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction time-locked ownership transfer mechanism with timestamp dependence vulnerability. The function now requires two separate transactions: first to initiate the transfer (storing pendingOwner and transferInitiatedAt), and second to complete it after a time delay. The vulnerability lies in using block.timestamp for critical timing logic, which can be manipulated by miners within the 900-second tolerance. This creates a stateful, multi-transaction vulnerability where miners can influence the timing of ownership transfers by manipulating block timestamps across multiple transactions. The contract state persists between transactions, making the vulnerability exploitable through timing manipulation across transaction boundaries.
 * 
 * Note: This code assumes additional state variables would be added to the contract:
 * - address public pendingOwner;
 * - uint256 public transferInitiatedAt;
 * - uint256 public constant TRANSFER_DELAY = 24 hours;
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
  address public pendingOwner;
  uint256 public transferInitiatedAt;
  uint256 public constant TRANSFER_DELAY = 1 days;

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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Multi-transaction time-locked ownership transfer
    if (pendingOwner == address(0)) {
        // First transaction: initiate ownership transfer
        pendingOwner = newOwner;
        transferInitiatedAt = block.timestamp;
        return;
    }
    // Second transaction: complete ownership transfer after time delay
    require(pendingOwner == newOwner, "Ownership transfer mismatch");
    require(block.timestamp >= transferInitiatedAt + TRANSFER_DELAY, "Transfer delay not met");
    // Vulnerable: Using block.timestamp for critical timing logic
    // Miners can manipulate timestamp within 900-second tolerance
    uint256 timeElapsed = block.timestamp - transferInitiatedAt;
    // Complete the transfer
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Reset pending transfer state
    pendingOwner = address(0);
    transferInitiatedAt = 0;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
