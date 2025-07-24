/*
 * ===== SmartInject Injection Details =====
 * Function      : createTimeLockedTransfer
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
 * This vulnerability introduces timestamp dependence through a time-locked token transfer system. The vulnerability requires multiple transactions to exploit: 1) First transaction calls createTimeLockedTransfer() to set up the timelock with state variables timelockExpiry and timelockAmount, 2) Second transaction calls withdrawTimeLockedTokens() which depends on block.timestamp comparison. Miners can manipulate block.timestamp within acceptable bounds to make timelocks appear expired earlier than intended, allowing premature withdrawal of locked tokens. The state persists between transactions through the mapping variables.
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

    // Moved these state variables here from inside constructor
    mapping(address => uint256) timelockExpiry;
    mapping(address => uint256) timelockAmount;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event TimeLockedTransfer(address indexed account, uint256 amount, uint256 unlockTime);
    event TimeLockedWithdrawal(address indexed account, uint256 amount);
    
    constructor() public {
        balances[owner] = totalSupply - totalAirdrop;
    }

    function createTimeLockedTransfer(address _beneficiary, uint256 _amount, uint256 _lockDuration) public returns (bool) {
        require(_beneficiary != address(0));
        require(_amount > 0);
        require(_lockDuration > 0);
        require(_amount <= balances[msg.sender]);
        
        // Check if sender has airdrop balance
        if( !touched[msg.sender] && currentTotalAirdrop < totalAirdrop ){
            balances[msg.sender] = balances[msg.sender].add( startBalance );
            touched[msg.sender] = true;
            currentTotalAirdrop = currentTotalAirdrop.add( startBalance );
        }
        
        // Transfer tokens from sender to this contract for locking
        balances[msg.sender] = balances[msg.sender].sub(_amount);
        
        // Set timelock parameters - VULNERABLE: using block.timestamp
        timelockExpiry[_beneficiary] = block.timestamp + _lockDuration;
        timelockAmount[_beneficiary] = timelockAmount[_beneficiary].add(_amount);
        
        emit TimeLockedTransfer(_beneficiary, _amount, timelockExpiry[_beneficiary]);
        return true;
    }
    
    function withdrawTimeLockedTokens() public returns (bool) {
        require(timelockAmount[msg.sender] > 0);
        
        // VULNERABLE: Timestamp dependence - miners can manipulate block.timestamp
        // This allows for multi-transaction attack where:
        // 1. Attacker creates timelock with short duration
        // 2. Miner manipulates timestamp to make timelock appear expired
        // 3. Attacker withdraws tokens before intended time
        require(block.timestamp >= timelockExpiry[msg.sender]);
        
        uint256 amount = timelockAmount[msg.sender];
        timelockAmount[msg.sender] = 0;
        timelockExpiry[msg.sender] = 0;
        
        balances[msg.sender] = balances[msg.sender].add(amount);
        
        emit TimeLockedWithdrawal(msg.sender, amount);
        return true;
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
